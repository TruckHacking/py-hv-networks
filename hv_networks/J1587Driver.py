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

from hv_networks import J1708Driver
import struct
import threading
import select
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
TRANSPORT_PIDS = [MGMT_PID,DAT_PID]
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


class J1587ReceiveSession(threading.Thread):
    def __init__(self, rts_raw, out_queue, mailbox, parent_stopped):
        super(J1587ReceiveSession, self).__init__(name="J1587ReceiveSession")
        self.rts = parse_conn_frame(rts_raw)
        self.my_mid = self.rts.dst
        self.other_mid = self.rts.src
        self.in_queue = queue.Queue()
        self.out_queue = out_queue
        self.mailbox = mailbox
        self.parent_stopped = parent_stopped

    def run(self):
        segments = self.rts.segments
        length = self.rts.length
        segment_buffer = [None] * segments
        cts = CTS_FRAME(self.my_mid,self.other_mid,segments,1)
        if self.parent_stopped.is_set():
            return
        self.out_queue.put(cts.to_buffer())
        start_time = time.time()
        while (not self.parent_stopped.is_set()) and None in segment_buffer and time.time() - start_time < 60:
            msg = None
            try:
                msg = self.in_queue.get(block=True,timeout=2)
            except queue.Empty:
                if self.parent_stopped.is_set():
                    return
                for i in range(segments):
                    if segment_buffer[i] is None:
                        cts = CTS_FRAME(self.my_mid,self.other_mid,1,i+1)
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
                self.out_queue.put(abort.to_buffer())
            return #timed out

        eom = EOM_FRAME(self.my_mid,self.other_mid)
        for i in range(3):
            self.out_queue.put(eom.to_buffer())
        data = bytes([self.other_mid])
        for segment in segment_buffer:
            data += segment.segment_data

        self.mailbox.put(data)

    def give(self,msg):
        self.in_queue.put(msg)

    def join(self, timeout=None):
        super(J1587ReceiveSession, self).join(timeout=timeout)


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
        self.out_queue.put(rts.to_buffer())

        if self.preempt_cts:  # special handling when we want to ignore any target CTS frames: just send it all
            for i in range(len(data_frames)):
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
                    self.out_queue.put(data_frames[base+i].to_buffer())
            else:
                pass#Either a RTS or RSD frame...why?

        if eom_recvd:
            self.success.set()

    def give(self,msg):
        self.in_queue.put(msg)

    def join(self, timeout=None):
        super(J1587SendSession,self).join(timeout=timeout)


class J1708DriverFactory:
    def __init__(self):
        self.ports = None
        self.set_ecm_ports()

    def set_ports(self, ports):
        self.ports = ports

    def set_ecm_ports(self):
        self.set_ports(J1708Driver.ECM)

    def set_dpa_ports(self):
        self.set_ports(J1708Driver.DPA)

    def set_plc_ports(self):
        self.set_ports(J1708Driver.DPA)

    def make(self):
        return J1708Driver.J1708Driver(self.ports)


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
    def __init__(self,read_queue):
        super(J1708WorkerThread,self).__init__(name="J1708WorkerThread")
        self.read_queue = read_queue
        self.stopped = threading.Event()
        self.a_lock = threading.Lock()
        with self.a_lock:
            self.driver = get_j1708_driver_factory().make()

    def run(self):
        while not self.stopped.is_set():
            msg = self.driver.read_message(checksum=True,timeout=0.1)
            if msg is not None:
                self.read_queue.put(msg)

        self.driver.close()
        del(self.driver)

    def join(self,timeout=None):
        self.stopped.set()
        super(J1708WorkerThread,self).join(timeout=timeout)

    def send_message(self,msg,has_check=False):
        # FIXME: not performant but lock needed b/c called from thread where self.driver isn't necessarily published yet
        with self.a_lock:
            self.driver.send_message(msg,has_check)


class J1587WorkerThread(threading.Thread):
    def __init__(self, my_mid, suppress_fragments, preempt_cts, silent, reassemble_others):
        super(J1587WorkerThread, self).__init__(name="J1587WorkerThread")
        self.my_mid = my_mid
        self.suppress_fragments = suppress_fragments
        self.preempt_cts = preempt_cts
        self.silent = silent
        self.reassemble_others = reassemble_others
        self.read_queue = multiprocessing.Queue()
        self.send_queue = multiprocessing.Queue()
        self.mailbox = multiprocessing.Queue()
        self.sessions = {}
        self.worker = J1708WorkerThread(self.read_queue)
        self.stopped = threading.Event()
        self.worker.start()

    def run(self):
        while not self.stopped.is_set():
            qs = select.select([self.read_queue._reader,self.send_queue._reader],[],[],1)[0]
            if qs is []:
                continue
            if self.stopped.is_set():
                return  # FIXME: there is still a race where the *_queue.get() can error out.
            for q in qs:
                if q is self.read_queue._reader:
                    while (not self.stopped.is_set()) and (not self.read_queue.empty()):
                        try:
                            msg = self.read_queue.get()
                            self.handle_message(msg)
                        except OSError:
                            if self.stopped.is_set():
                                return
                            else:
                                raise
                else:
                    while (not self.stopped.is_set()) and (not self.send_queue.empty()):
                        try:
                            msg = self.send_queue.get()
                            if not self.silent:
                                self.worker.send_message(msg)
                        except OSError:
                            if self.stopped.is_set():
                                return
                            else:
                                raise

    # Note: src and dst are wrt _send_ sessions
    def get_session(self, src, dst):
        return self.sessions.get((src, dst), None)

    # Note: src and dst are wrt _send_ sessions
    def update_session(self, src, dst, value):
        self.sessions.update({(src, dst): value})

    def handle_message(self,msg):
        if len(msg) < 4 or msg[1] not in TRANSPORT_PIDS:
            self.mailbox.put(msg)
        else:
            if not self.suppress_fragments:
                self.mailbox.put(msg)
            if not msg[3] == self.my_mid:  # connection message not for us
                if not self.reassemble_others:
                    return

            src = msg[3]
            dst = msg[0]
            known_session = self.get_session(src, dst)
            if (known_session is not None) and known_session.is_alive():
                known_session.give(msg)
            else:
                if is_rts_frame(msg):
                    parent_stopped = self.stopped
                    session = J1587ReceiveSession(msg, self.send_queue, self.mailbox, parent_stopped)
                    self.update_session(src, dst, session)
                    session.start()
                else:
                    abort = ABORT_FRAME(self.my_mid, dst)
                    self.send_queue.put(abort.to_buffer())

    def read_message(self,block=True,timeout=None):
        return self.mailbox.get(block=block,timeout=timeout)

    def send_message(self,msg):
        self.send_queue.put(msg)

    def transport_send(self,dst,msg):
        parent_stopped = self.stopped
        success = threading.Event()
        send_session = J1587SendSession(self.my_mid, dst, msg, self.send_queue, success, parent_stopped,
                                        self.preempt_cts)
        self.update_session(self.my_mid, dst, send_session)
        send_session.start()
        send_session.join()
        if not success.is_set():
            raise TimeoutException("J1587 send either aborted or timed out")

    def join(self,timeout=None):
        self.worker.join()
        self.stopped.set()
        # the queue's threads keep running, close them cleanly
        self.send_queue.close()
        self.mailbox.close()
        super(J1587WorkerThread,self).join(timeout=timeout)
        # the sessions's threads keep running, close them cleanly
        self.read_queue.close()
        for k,s in self.sessions.items():
            s.join(timeout)


class J1587Driver():
    '''
    Class for J1587 comms. Abstracts transport layer and PID requests.
    my_mid: the 'source' MID of this driver. Listens for transport frames destined to this MID. send_message() ignores
        this value.
    suppress_fragments: do not return transport fragments from read_message(). default True.
    preempt_cts: send transport fragments without waiting for target node CTS. default False.
    silent: do not send any messages (e.g. responses to transport frames). default False
    reassemble_others: track, respond to and reassemble transport frames destines for nodes other than my_mid.
        default False.
    '''
    def __init__(self, my_mid, suppress_fragments=True, preempt_cts=False, silent=False, reassemble_others=False):
        self.my_mid = my_mid
        self.J1587Thread = J1587WorkerThread(self.my_mid, suppress_fragments, preempt_cts, silent, reassemble_others)
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
            if pid < 255:
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

