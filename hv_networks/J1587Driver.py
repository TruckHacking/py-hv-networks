#    J1587Driver: a clusterfsck of a J1587 transport layer implementation
#    Copyright (C) 2016  Haystack (haystackinfosec@gmail.com)

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>
import enum
import os
import sys
from types import SimpleNamespace

if os.name == 'nt':
    from RP1210 import RP1210

from hv_networks import J1708Driver
import threading
import queue
import time
import multiprocessing
RTS = 1
CTS = 2
EOM = 3
RSD = 4
ABORT = 255

class AbortException(Exception):
    def __init__(self,value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class TimeoutException(Exception):
    def __init__(self,value):
        self.value = value

    def __str__(self):
        return repr(self.value)


MGMT_PID = 197
DAT_PID = 198
TRANSPORT_PIDS = [MGMT_PID, DAT_PID]
MULTISECTION_PID = 192


class conn_mgmt_frame():
    def __init__(self,src=None,dst=None,conn_mgmt=None):
        self.src = src
        self.dst = dst
        self.conn_mgmt = conn_mgmt


class RTS_FRAME(conn_mgmt_frame):
    def __init__(self,src,dst,segments,length):
        super().__init__(src,dst,RTS)
        self.segments = segments
        self.length = length

    def to_buffer(self):
        return bytes([self.src,MGMT_PID,5,self.dst,self.conn_mgmt,self.segments,self.length & 0xFF,(self.length & 0xFF00) >> 8])

class CTS_FRAME(conn_mgmt_frame):
    def __init__(self,src,dst,num_segments,next_segment):
        super().__init__(src,dst,CTS)
        self.num_segments = num_segments
        self.next_segment = next_segment

    def to_buffer(self):
        return bytes([self.src,MGMT_PID,4,self.dst,self.conn_mgmt,self.num_segments,self.next_segment])

class EOM_FRAME(conn_mgmt_frame):
    def __init__(self,src,dst):
        super().__init__(src,dst,EOM)

    def to_buffer(self):
        return bytes([self.src,MGMT_PID,2,self.dst,self.conn_mgmt])


class RSD_FRAME(conn_mgmt_frame):
    def __init__(self,src,dst,request):
        super().__init__(src,dst,RSD)
        self.request = request

    def to_buffer(self):
        return bytes([self.src,MGMT_PID,4,self.dst,self.conn_mgmt,self.request & 0xFF,(self.request & 0xFF00) >> 8])

class ABORT_FRAME(conn_mgmt_frame):
    def __init__(self,src,dst):
        super().__init__(src,dst,ABORT)

    def to_buffer(self):
        return bytes([self.src,MGMT_PID,2,self.dst,self.conn_mgmt])


def parse_conn_frame(buf):
    src = buf[0]
    frame_bytes = buf[2]
    dst = buf[3]
    conn_mgmt = buf[4]
    if conn_mgmt == RTS:
        num_segments = buf[5]
        total_bytes = (buf[7] << 8) | buf[6]
        return RTS_FRAME(src,dst,num_segments,total_bytes)
    elif conn_mgmt == CTS:
        num_segments = buf[5]
        next_segment = buf[6]
        return CTS_FRAME(src,dst,num_segments,next_segment)
    elif conn_mgmt == EOM:
        return EOM_FRAME(src,dst)
    elif conn_mgmt == RSD:
        request = (buf[6] << 8) | buf[5]
        return RSD_FRAME(src,dst,request)
    elif conn_mgmt == ABORT:
        return ABORT_FRAME(src,dst)
    else:
        raise Exception("unrecognized conn_mgmt command code")

def is_conn_frame(buf):
    return len(buf) >= 5 and buf[1] == MGMT_PID

def is_rts_frame(buf):
    return is_conn_frame(buf) and buf[4] == RTS

def is_abort_frame(buf):
    return is_conn_frame(buf) and buf[4] == ABORT


class conn_mode_transfer_frame():
    def __init__(self,src,dst,segment_id,segment_data):
        self.src = src
        self.dst = dst
        self.segment_id = segment_id
        self.segment_data = segment_data

    def to_buffer(self):
        return bytes([self.src,DAT_PID,2+len(self.segment_data),self.dst,self.segment_id])+self.segment_data

def parse_data_frame(buf):

    src = buf[0]
    dst = buf[3]
    segment_id = buf[4]
    segment_data = buf[5:]

    return conn_mode_transfer_frame(src,dst,segment_id,segment_data)

def is_data_frame(buf):
    return len(buf) >= 6 and buf[1] == DAT_PID


class J1587TransportReceiveSession(threading.Thread):
    def __init__(self, rts_raw, out_queue, parent, parent_stopped):
        super(J1587TransportReceiveSession, self).__init__(name="J1587TransportReceiveSession")
        self.rts = parse_conn_frame(rts_raw)
        self.my_mid = self.rts.dst
        self.other_mid = self.rts.src
        self.in_queue = queue.Queue()
        self.out_queue = out_queue
        self.parent = parent
        self.parent_stopped = parent_stopped

    def run(self):
        segments = self.rts.segments
        length = self.rts.length
        segment_buffer = [None] * segments
        cts = CTS_FRAME(self.my_mid,self.other_mid,segments,1)
        if self.parent_stopped.is_set():
            return
        if self.out_queue:
            self.out_queue.put(cts.to_buffer())
        start_time = time.time()
        while (not self.parent_stopped.is_set()) and None in segment_buffer and time.time() - start_time < 60:
            msg = None
            try:
                msg = self.in_queue.get(block=True,timeout=2)  # FIXME: magic number 2
            except queue.Empty:
                if self.parent_stopped.is_set():
                    return
                for i in range(segments):
                    if segment_buffer[i] is None:
                        cts = CTS_FRAME(self.my_mid,self.other_mid,1,i+1)
                        if self.out_queue:
                            self.out_queue.put(cts.to_buffer())
                        time.sleep(.1)
            if msg is None:
                continue

            if is_abort_frame(msg):
                break
            elif is_rts_frame(msg):
                continue
            elif is_conn_frame(msg):
                abort = ABORT_FRAME(self.my_mid,self.other_mid)
                for i in range(3):
                    if self.out_queue:
                        self.out_queue.put(abort.to_buffer())
                    break
            elif is_data_frame(msg):
                dat = parse_data_frame(msg)
                segment_buffer[dat.segment_id-1] = dat
            else:
                raise Exception("J1587 Session Thread shouldn't have received %s" % repr(msg))

        if self.parent_stopped.is_set():
            return

        if None in segment_buffer:
            abort = ABORT_FRAME(self.my_mid,self.other_mid)
            for i in range(3):
                if self.out_queue:
                    self.out_queue.put(abort.to_buffer())
            return #timed out

        eom = EOM_FRAME(self.my_mid,self.other_mid)
        for i in range(3):
            if self.out_queue:
                self.out_queue.put(eom.to_buffer())
        data = bytes([self.other_mid])
        for segment in segment_buffer:
            data += segment.segment_data

        self.parent.message_received(data, has_checksum=False)

    def give(self,msg):
        self.in_queue.put(msg)

    def join(self, timeout=None):
        super(J1587TransportReceiveSession, self).join(timeout=timeout)


class J1587SendSession(threading.Thread):
    def __init__(self, src, dst, msg, out_queue, success, parent_stopped, preempt_cts):
        super(J1587SendSession, self).__init__(name="J1587SendSession")
        self.src = src
        self.dst = dst
        self.msg = msg
        self.out_queue = out_queue
        self.in_queue = queue.Queue()
        self.success = success
        self.parent_stopped = parent_stopped
        self.preempt_cts = preempt_cts

    def run(self):
        data_list = []
        data_frames = []
        #chop up data
        msg = self.msg
        data_len = len(msg)
        while len(msg) > 0:
            data_list += [msg[:15]]  # FIXME: magic number 15 should be J1587_TRANSPORT_SEGMENT_SIZE
            msg = msg[15:]

        #package data into transfer frames
        i = 1
        for el in data_list:
            frame = conn_mode_transfer_frame(self.src,self.dst,i,el)
            data_frames += [frame]
            i += 1

        #send rts
        rts = RTS_FRAME(self.src,self.dst,len(data_frames),data_len)
        if self.parent_stopped.is_set():
            return
        if self.out_queue:
            self.out_queue.put(rts.to_buffer())

        if self.preempt_cts:  # special handling when we want to ignore any target CTS frames: just send it all
            for i in range(len(data_frames)):
                if self.out_queue:
                    self.out_queue.put(data_frames[i].to_buffer())
            self.success.set()
            return

        #otherwise begin sending loop
        eom_recvd = False
        start_time = time.time()
        while (not self.parent_stopped.is_set()) and (not eom_recvd) and time.time() - start_time < 10:
            try:
                msg = self.in_queue.get(block=True,timeout=2)
            except queue.Empty:
                time.sleep(3)
                continue
            if not is_conn_frame(msg):
                raise Exception("J1587SendSession should not receive %s" % repr(msg))

            frame = parse_conn_frame(msg)
            if frame.conn_mgmt == EOM:
                eom_recvd = True
                continue
            elif frame.conn_mgmt == ABORT:
                break
            elif frame.conn_mgmt == CTS:
                base = frame.next_segment - 1
                for i in range(frame.num_segments):
                    if self.out_queue:
                        self.out_queue.put(data_frames[base+i].to_buffer())
            else:
                pass#Either a RTS or RSD frame...why?

        if eom_recvd:
            self.success.set()

    def give(self,msg):
        self.in_queue.put(msg)

    def join(self, timeout=None):
        super(J1587SendSession,self).join(timeout=timeout)


DEFAULT_J1708_INTERFACE = 'j1708'
if os.name == 'nt':
    DEFAULT_J1708_INTERFACE = 'RP1210'

class J1708DriverFactory:
    def __init__(self):
        self.device_id = None
        self.dll_name = None
        self.ports = None
        self.truckduck_address = 'localhost'
        self.set_ecm_ports()
        self.rp1210 = False

    def set_ports(self, ports):
        self.ports = ports

    def set_ecm_ports(self):
        self.set_ports(J1708Driver.ECM)

    def set_dpa_ports(self):
        self.set_ports(J1708Driver.DPA)

    def set_plc_ports(self):
        self.set_ports(J1708Driver.DPA)

    @staticmethod
    def argparse(parser):
        parser.add_argument('--j1708-interface', default=DEFAULT_J1708_INTERFACE, const=DEFAULT_J1708_INTERFACE,
                            nargs='?', choices=['truckduck_1', 'j1708', 'truckduck_2', 'j1708_2', 'truckduck_bbplc',
                                                'plc', 'RP1210', 'rp1210'],
                            help='choose the interface to send and receive J1708 messages. Truckduck interfaces use '
                                 'localhost by default. RP1210 J1708 interface is available on 32bit python running '
                                 'on windows when VDA drivers are installed and configured.')
        parser.add_argument('--truckduck-host', default='localhost', nargs='?',
                            help='specify the network hostname of the target truckduck. For non-localhost you will '
                                 'need to start port redirects on the target host.')
        parser.add_argument('--rp1210-dll', nargs='?', help='the RP1210 dll name to use. uses first DLL if omitted.')
        parser.add_argument('--rp1210-device', nargs='?', help='the RP1210 device id to use. Default is 1.',
                            default=1, type=int)
        parser.add_argument('--list-rp1210', help='list the RP1210 DLLs and Devices.', action='store_true')

    def parse_args(self, args):
        if args.j1708_interface in ['truckduck_1', 'j1708']:
            self.set_ecm_ports()
        elif args.j1708_interface in ['truckduck_2', 'j1708_2']:
            self.set_dpa_ports()
        elif args.j1708_interface in ['truckduck_bbplc', 'plc']:
            self.set_dpa_ports()
        elif args.j1708_interface in ['RP1210', 'rp1210']:
            if not os.name == 'nt':
                sys.stderr.write('RP1210 only supported in 32bit python on windows\n')
                sys.exit(1)
            self.rp1210 = True

        if args.truckduck_host:
            # TODO print a one-liner to run the needed redirects on the truckduck
            self.truckduck_address = args.truckduck_host

        if os.name == 'nt':
            if args.list_rp1210:
                for dll_name in RP1210.getAPINames():
                    sys.stderr.write(f"DLL: {dll_name}\n")
                    config = RP1210.RP1210Config(dll_name)
                    for device in config.getDevices():
                        sys.stderr.write(f"Device ID: {device.getID()}\n")
                        sys.stderr.write(f"Device Description: {device.getDescription()}\n")
                        sys.stderr.write(f"Device Name: {device.getName()}\n")
                        sys.stderr.write(f"Device Params: {device.getParams()}\n")
                    sys.stderr.write(f"Protocols: {config.getProtocolNames()}\n\n")
                sys.stderr.flush()
                sys.exit(1)

            if args.rp1210_dll:
                self.dll_name = args.rp1210_dll
            else:
                self.dll_name = RP1210.getAPINames()[0]

            if args.rp1210_device:
                self.device_id = args.rp1210_device
                client = RP1210.RP1210Client()
                client.setVendor(self.dll_name)
                client.setDevice(self.device_id)

                config = RP1210.RP1210Config(self.dll_name)
                protocols = config.getProtocolNames()
                if 'J1708' not in protocols and 'PLC' not in protocols:
                    sys.stderr.write("device %d does not support j1708 %s\n" % (self.device_id, protocols))
                    sys.exit(1)

    def make(self):
        if self.rp1210:
            client = RP1210.RP1210Client()
            client.setVendor(self.dll_name)
            client.setDevice(self.device_id)

            config = RP1210.RP1210Config(self.dll_name)
            protocol = b"J1708"
            if protocol not in config.getProtocolNames():
                protocol = b"PLC"
            client.connect(protocol + b":Baud=9600")
            return J1708Driver.RP1210J1708Driver(client)
        else:
            return J1708Driver.J1708Driver(ports=self.ports, host=self.truckduck_address)


factory_lock = threading.Lock()
j1708_factory_singleton = J1708DriverFactory()


def set_j1708_driver_factory(factory):
    global j1708_factory_singleton
    with factory_lock:
        j1708_factory_singleton = factory


def get_j1708_driver_factory():
    with factory_lock:
        a = j1708_factory_singleton
    return a


class J1708WorkerThread(threading.Thread):
    def __init__(self, read_queue, loopback):
        super(J1708WorkerThread,self).__init__(name="J1708WorkerThread")
        self.read_queue = read_queue
        self.loopback = loopback
        self.stopped = threading.Event()
        self.a_lock = threading.Lock()
        with self.a_lock:
            self.driver = get_j1708_driver_factory().make()

    def run(self):
        while not self.stopped.is_set():
            msg = self.driver.read_message(checksum=True,timeout=0.1)  # FIXME: magic number 0.1
            if msg is not None:
                msg = bytes(msg)
                self.read_queue.put(msg)

        self.driver.close()
        del(self.driver)

    def join(self,timeout=None):
        self.stopped.set()
        super(J1708WorkerThread,self).join(timeout=timeout)

    def send_message(self,msg,has_check=False):
        # FIXME: not performant but lock needed b/c called from thread where self.driver isn't necessarily published yet
        if self.stopped.is_set():
            return
        with self.a_lock:
            self.driver.send_message(msg, has_check)
        if self.loopback:
            self.read_queue.put(J1708Driver.J1708Driver.prepare_message(msg, has_check))


class InOutTags(enum.Enum):
    Send = 1
    Read = 2


class TaggingPutOnlyQueue():
    def __init__(self, q: multiprocessing.Queue, tag: InOutTags):
        self.tag = tag
        self.q = q

    def put(self, obj):
        self.q.put([self.tag, obj])


class J1587WorkerThread(threading.Thread):
    def __init__(self, my_mid, suppress_fragments, preempt_cts, silent, reassemble_others, pass_invalid_messages,
                 loopback):
        super(J1587WorkerThread, self).__init__(name="J1587WorkerThread")
        self.my_mid = my_mid
        self.suppress_fragments = suppress_fragments
        self.preempt_cts = preempt_cts
        self.silent = silent
        self.reassemble_others = reassemble_others
        self.pass_invalid_messages = pass_invalid_messages
        self.loopback = loopback
        self.uni_queue = multiprocessing.Queue()
        self.read_queue = TaggingPutOnlyQueue(self.uni_queue, InOutTags.Read)
        self.send_queue = TaggingPutOnlyQueue(self.uni_queue, InOutTags.Send)
        self.mailbox = multiprocessing.Queue()
        self.transport_sessions = {}
        self.multisection_sessions = {}
        self.worker = J1708WorkerThread(self.read_queue, loopback)  # puts messages with checksum onto read_queue
        self.stopped = threading.Event()
        self.worker.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                tag, msg = self.uni_queue.get(block=True, timeout=1.0)
                if tag == InOutTags.Read:
                    try:
                        test_checksum = J1708Driver.J1708Driver.prepare_message(msg[:-1], has_checksum=False)[-1]
                        if test_checksum != msg[-1]:
                            if self.pass_invalid_messages:
                                self.message_received(msg)
                        else:
                            self.handle_message(msg)
                    except OSError:
                        if self.stopped.is_set():
                            return
                        else:
                            raise
                else:
                    try:
                        self.worker.send_message(msg)
                    except OSError:
                        if self.stopped.is_set():
                            return
                        else:
                            raise
            except queue.Empty:
                continue

    def message_received(self, msg, has_checksum):
        if has_checksum:
            msg = msg[:-1]
        self.mailbox.put(msg)

    # Note: src and dst are wrt _send_ sessions
    def get_transport_session(self, src, dst):
        return self.transport_sessions.get((src, dst), None)

    # Note: src and dst are wrt _send_ sessions
    def update_transport_session(self, src, dst, value):
        self.transport_sessions.update({(src, dst): value})

    def update_multisection_session(self, src_mid, target_pid, session):
        return self.multisection_sessions.update({(src_mid, target_pid): session})

    def clear_multisection_session(self, src_mid, target_pid):
        return self.multisection_sessions.pop((src_mid, target_pid))

    def get_multisection_session(self, src_mid, target_pid):
        return self.multisection_sessions.get((src_mid, target_pid), None)

    def handle_message(self, msg):
        if len(msg) < 2:
            if self.pass_invalid_messages:
                self.message_received(msg, has_checksum=True)
            return  # not valid J1587
        if msg[1] in TRANSPORT_PIDS:
            if len(msg) < 4:  # too short, maybe invalid: in any case pass-on for receive
                self.message_received(msg, has_checksum=True)
                return
            if not self.suppress_fragments:
                self.message_received(msg, has_checksum=True)

            dst = msg[3]
            if not dst == self.my_mid:  # connection message not for us
                if not self.reassemble_others:
                    return
            self.handle_transport_message(dst, msg[0], msg[:-1])  # takes message w/o checksum
        elif msg[1] == MULTISECTION_PID:
            if not self.suppress_fragments:
                self.message_received(msg, has_checksum=True)

            self.handle_multisection_message(msg[:-1])  # takes message w/o checksum
        else:
            self.message_received(msg, has_checksum=True)

    def handle_transport_message(self, dst, src, msg_no_checksum):
        known_session = self.get_transport_session(dst, src)
        if (known_session is not None) and known_session.is_alive():
            known_session.give(msg_no_checksum)
        else:
            if is_rts_frame(msg_no_checksum):
                parent_stopped = self.stopped
                session = J1587TransportReceiveSession(msg_no_checksum,
                                                       None if self.silent else self.send_queue,
                                                       self,
                                                       parent_stopped)
                self.update_transport_session(dst, src, session)
                session.start()
            else:
                abort = ABORT_FRAME(self.my_mid, src)
                if not self.silent:
                    self.send_queue.put(abort.to_buffer())

    def handle_multisection_message(self, msg_no_checksum):
        if len(msg_no_checksum) < 5:  # too short, maybe invalid, in any case pass-on for receive
            self.message_received(msg_no_checksum, has_checksum=False)
            return
        src = msg_no_checksum[0]
        target_pid = msg_no_checksum[3]
        section_final = (msg_no_checksum[4] & 0xF0) >> 4
        section_this = (msg_no_checksum[4] & 0x0F)
        if section_this == 0:  # this is the first frame ('section')
            session = SimpleNamespace(target_len=msg_no_checksum[5],
                                      last_seen_section=0,
                                      acc_bytes=msg_no_checksum[6:])  # data starts at index 6 in first frame
            self.update_multisection_session(src, target_pid, session)
        else:
            session = self.get_multisection_session(src, target_pid)
            if session is None:  # invalid, in any case pass-on for receive
                self.message_received(msg_no_checksum, has_checksum=False)
                return

            if session.last_seen_section + 1 != section_this:  # invalid, in any case pass-on for receive
                self.clear_multisection_session(src, target_pid)
                self.message_received(msg_no_checksum, has_checksum=False)
                return

            session.last_seen_section = section_this
            session.acc_bytes += msg_no_checksum[5:]  # data starts at index 5 in subsequent frames

            if section_this == section_final and len(session.acc_bytes) == session.target_len:  # all received
                final = bytes([src, target_pid])
                final += bytes([len(session.acc_bytes)])
                final += session.acc_bytes
                self.message_received(final, has_checksum=False)
                self.clear_multisection_session(src, target_pid)
            else:
                self.update_multisection_session(src, target_pid, session)

    def read_message(self,block=True,timeout=None):
        return self.mailbox.get(block=block,timeout=timeout)

    def send_message(self,msg):
        self.send_queue.put(msg)

    def transport_send(self,dst,msg):
        parent_stopped = self.stopped
        success = threading.Event()
        send_session = J1587SendSession(self.my_mid, dst, msg,
                                        None if self.silent else self.send_queue, success, parent_stopped,
                                        self.preempt_cts)
        self.update_transport_session(self.my_mid, dst, send_session)
        send_session.start()
        send_session.join()
        if not success.is_set():
            raise TimeoutException("J1587 send either aborted or timed out")

    def join(self,timeout=None):
        self.worker.join()
        self.stopped.set()
        # the queue's threads keep running, close them cleanly
        self.mailbox.close()
        super(J1587WorkerThread,self).join(timeout=timeout)
        # the transport_sessions's threads keep running, close them cleanly
        self.uni_queue.close()
        for k,s in self.transport_sessions.items():
            s.join(timeout)


class J1587Driver():
    '''
    Class for J1587 comms. Abstracts transport layer and PID requests.
    my_mid: the 'source' MID of this driver. Listens for transport frames destined to this MID. send_message() ignores
        this value.
    suppress_fragments: do not return transport fragments from read_message(). default True.
    preempt_cts: send transport fragments without waiting for target node CTS. default False.
    silent: do not send any messages (e.g. responses to transport frames). default False
    reassemble_others: track, respond to and reassemble transport frames destined for nodes other than my_mid.
        default False.
    pass_invalid_messages: when invalid J1587 messages (or non-J1587 messages) are encountered, pass them on to
        read_message() anyways
        default False.
    loopback: echo all sent messages back as read messages too. default False.
    '''
    def __init__(self, my_mid, suppress_fragments=True, preempt_cts=False, silent=False, reassemble_others=False,
                 pass_invalid_messages=False, loopback=False):
        self.my_mid = my_mid
        self.J1587Thread = J1587WorkerThread(self.my_mid, suppress_fragments, preempt_cts, silent, reassemble_others,
                                             pass_invalid_messages, loopback)
        self.J1587Thread.start()

    def read_message(self,block=True,timeout=None):
        '''
        Read a message from the bus. Will receive J1587 transport messages in reconstructed form.
        block: boolean that determines whether bus blocks or not
        timeout: Number of seconds to time out.
        '''
        return self.J1587Thread.read_message(block,timeout)

    def send_message(self,msg):
        '''
        Send a message using regular J1708. Currently always assumes there is no checksum.

        msg: byte string that is message to send.
        '''
        self.J1587Thread.send_message(msg)

    def transport_send(self,dst,msg):
        '''
        Sends a message of any length using J1587 transport.

        dst: destination MID
        msg: byte string of message, without MID.
        '''
        self.J1587Thread.transport_send(dst,msg)

    def pid_send(self, pid, data):
        '''
        Sends a PID and data, breaks into multisection parameter if the data + PID is longer than 21 bytes
        :param pid: the PID
        :param data:  the data
        '''
        raise NotImplemented("FIXME implement this")

    def request_pid(self,mid,pid):
        '''Request PID from a specific MID.
        MID: MID of device from which we want the response.
        PID: The PID to be requested.
        '''

        start_time = time.time()
        timeout = .08
        recvd = False
        response = None
        while not recvd and time.time() - start_time <= timeout:
            if pid < 255:  # FIXME: sends incomplete requests for extended page PIDs. It should use PID 256 for that
                request = bytes([self.my_mid,0,pid])
            else:
                request = bytes([self.my_mid,0,255,pid % 256])

            sent_time = time.time()
            self.send_message(request)
            response = self.read_message()
            while not (len(response) > 2 and response[0] == mid and response[1] == pid) and time.time() - sent_time < .02:
                response = self.read_message()
            if len(response) > 2 and response[1] == pid:
                recvd = True
            else:
                response = None

        return response

    def cleanup(self):
        self.J1587Thread.join()

    def __del__(self):
        self.J1587Thread.join(timeout=1)


if __name__ == '__main__':
    driver = J1587Driver(0xac)
    count = 0
    requests = [13,14,26,31,32,33,34,35,36,39,42,53,54,55,56,57,58,59,60,61,62,63,64,66,67,74,82,87,88,113,134,136,137,
		138,139,140,141,142,143,144,145,146,150,152,154,155,158,160,161,165,166,178,179,180,181,188,189,206,207,208,214,217,
		218,220,223,228,229,230,233,234,235,236,237,238,239,240,243,246,247,248,249,250,251,252,342,347,355,364,374,375,376,
		377,379,383,385,405,406,407,408,409,413,414,415,416,417,419,420,421,422,423,424,425,426,427,428,429,430,431,432,433,
		434,435,436,437,438,443,500,509,507,508]

    for request in requests:
        response = driver.request_pid(0x80,request) #FIXME: sends incomplete requests for extended page PIDs should use PID 256 for that
        if response is not None:
            count += 1
        print("Response for pid %d: %s" % (request,repr(response)))

    print("Total data elements received: %d" % count)

