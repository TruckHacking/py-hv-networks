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

import socket
import sys
import struct
from functools import reduce
import select

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
    def __init__(self,ports=ECM):
        self.serveport,self.clientport = ports
        self.sock = socket.socket(family=socket.AF_INET,type=socket.SOCK_DGRAM)
        try:
            self.sock.bind(('localhost',self.clientport))
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

    #buf: message to send as type bytes
    #has_check: True if your message includes checksum. Defaults to False.
    def send_message(self,buf,has_check=False):
        '''Send a message to the bus.
        buf: A byte string that forms a J1708 message.
        has_check: boolean that indicates whether your message has a checksum or not. If False, checksum will be calculated and appended.
        '''
        msg = buf
        if not has_check:
            check = struct.pack('b',checksum(msg))
            msg += check
        self.sock.sendto(msg,('localhost',self.serveport))

    def close(self):
        self.sock.close()

    def __del__(self):
        self.sock.close()

        

#Test to see if this works. Reads 10 messages, sends a CAT ATA SecuritySetup message.
#You should see a reply of the form \x80\xfe\xac\xf0\x?? if it works
if __name__ == '__main__':
    driver = J1708Driver(ECM)
    for i in range(0,10):
        print(repr(driver.read_message()))
    
    driver.send_message(b'\xAC\xFE\x80\xF0\x17')
    for i in range(0,10):
        print(repr(driver.read_message()))
