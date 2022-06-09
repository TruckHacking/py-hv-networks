#    J1708Driver: an RP1210-esque interface to the TruckDuck J1708 system.
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
import os
import socket
import struct
import time
from ctypes import c_char
from functools import reduce

import select

if os.name == 'nt':
    from RP1210 import RP1210Client

ECM = (6969,6970)
DPA = (6971,6972)


def toSignedChar(num):
    if type(num) is bytes:
        return struct.unpack('b',num)[0]
    else:
        return struct.unpack('b',struct.pack('B',num & 0xFF))[0]


def checksum(msg):
    return toSignedChar(~reduce(lambda x,y: (x + y) & 0xFF, list(msg)) + 1)


class J1708Driver():
    '''Driver class for J1708 messages. Requires that the ecm and/or non_ecm upstart tasks
       are running.
    '''
    def __init__(self, ports=ECM, host='localhost'):
        self.next_send_ns = time.monotonic_ns()
        self.serveport, self.clientport = ports
        self.host = host
        self.sock = socket.socket(family=socket.AF_INET,type=socket.SOCK_DGRAM)
        try:
            self.sock.bind((self.host, self.clientport))
        except OSError as e:
            print(e)

    #checksum: Checksum included in return value if True. Defaults to false.
    #returns the message read as bytes type.
    def read_message(self,checksum=False,timeout=0.5):
        '''Read a message from the bus.
        checksum: include checksum in return value; defaults to False.
        timeout: number of seconds to wait before timing out. None = wait indefinitely

        Returns byte string or None if timeout'''
        ready = select.select([self.sock],[],[],timeout)[0]
        if ready == []:
                return None
        else:
                message = self.sock.recv(256)
                if checksum:
                        return message
                else:
                        return message[:-1]

    BITS_PER_BYTE = 10  # yes, it's actually 10 if you include start and stop bits
    PREAMBLE_BIT_TIME_NS = 104000
    BODY_BIT_TIME_NS = 100000

    def send_message(self, buf, has_checksum=False):
        """
        Send a message to the bus.
        buf: A byte string that forms a J1708 message.
        has_checksum: boolean that indicates whether your message has a checksum or not. If False, checksum will be
        calculated and appended.
        """
        msg = self.prepare_message(buf, has_checksum)
        while True:
            if time.monotonic_ns() > self.next_send_ns:
                break
        self.sock.sendto(msg, (self.host, self.serveport))
        # set the pace based on J2497 timing instead of J1708, because it is slower
        self.next_send_ns = time.monotonic_ns() + \
            self.PREAMBLE_BIT_TIME_NS * 12 + \
            self.BODY_BIT_TIME_NS * (len(msg) * self.BITS_PER_BYTE + 5 + 5)

    @staticmethod
    def prepare_message(buf, has_checksum):
        msg = buf
        if not has_checksum:
            check = struct.pack('b', checksum(msg))
            msg += check
        return msg

    def close(self):
        self.sock.close()

    def __del__(self):
        self.sock.close()


class RP1210J1708Driver:
    def __init__(self, client):
        self.next_send_ns = time.monotonic_ns()
        self.client = client
        self.read_timeout = None

        self.client.setAllFiltersToPass()

    BUFFER_SIZE = 8192

    def update_blocking_io_timeout(self, timeout_s):
        self.client.setBlockingTimeout(int(timeout_s * 1000.0), 1)

    def read_message(self, checksum=False, timeout=0.1):
        api_buf = (c_char * self.BUFFER_SIZE)()

        if self.read_timeout != timeout:
            self.update_blocking_io_timeout(timeout)
        self.read_timeout = timeout
        then = time.monotonic()
        while True:
            if time.monotonic() - then > timeout:
                return None
            buffer = self.client.rx(buffer_size=256 + 5, blocking=1)
            if len(buffer) == 0:
                continue

            message = buffer[4:]
            if checksum:
                return J1708Driver.prepare_message(message, has_checksum=False)
            else:
                return message

    BITS_PER_BYTE = 10  # yes, it's actually 10 if you include start and stop bits
    PREAMBLE_BIT_TIME_NS = 104000
    BODY_BIT_TIME_NS = 100000

    def send_message(self, msg, has_checksum=False):
        if has_checksum:
            msg = msg[:-1]  # RP1210 wants none of that
        while True:
            if time.monotonic_ns() > self.next_send_ns:
                break

        j1708_request = bytearray()
        j1708_request.append(0)
        j1708_request.extend(msg)

        # set the pace based on J2497 timing instead of J1708, because it is slower
        self.next_send_ns = time.monotonic_ns() + \
            self.PREAMBLE_BIT_TIME_NS * 12 + \
            self.BODY_BIT_TIME_NS * (len(msg) * self.BITS_PER_BYTE + 5 + 5)
        self.client.tx(j1708_request)

    def close(self):
        if self.client:
            self.client.disconnect()
            self.client = None

    def __del__(self):
        self.close()


#Test to see if this works. Reads 10 messages, sends a CAT ATA SecuritySetup message.
#You should see a reply of the form \x80\xfe\xac\xf0\x?? if it works
if __name__ == '__main__':
    driver = J1708Driver(ECM)

    for i in range(0,10):
        print(repr(driver.read_message()))

    driver.send_message(b'\xAC\xFE\x80\xF0\x17')
    for i in range(0,10):
        print(repr(driver.read_message()))
