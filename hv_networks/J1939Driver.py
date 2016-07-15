#    J1939Driver: an RP1210-esque Python interface to kurt-vd's J1939 sockets
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
import time

class J1939Driver():
    def __init__(self, my_sa=0xF9, interface='can0'):
        self.my_sa = my_sa
        self.interface = interface
        self.can_socket = socket.socket(socket.PF_CAN, socket.SOCK_DGRAM,
                                        socket.CAN_J1939)
        addr_set = False
        while self.my_sa < 256 and not addr_set:
            try:
                self.can_socket.bind((self.interface,socket.J1939_NO_NAME,socket.J1939_NO_PGN,self.my_sa))
            except OSError:
                print("Failed to bind %s with id %d" % (self.interface, self.my_sa))
                self.my_sa += 1
            except Exception as e:
                raise e
            else:
                addr_set = True
        if not addr_set:
            try:
                self.can_socket.bind((self.interface, socket.J1939_NO_NAME, socket.J1939_NO_PGN, 0xff))
                self.my_sa = 0xff
            except Exception as e:
                print("last-try binding failed: %s" % (repr(e)))

        self.can_socket.settimeout(5)
        socket.CMSG_SPACE(1) + socket.CMSG_SPACE(8)#what does this do?

    def unbind(self):
        self.can_socket.close()

    def send_message(self, priority, pgn, sdata, sa=249,da = 0xFF):
        '''
        Send a message over J1939.
        priority: message priority.
        pgn: message PGN
        sdata: byte string of J1939 data
        sa: source address, though behavior with sas other than bound sa is unknown right now.
        da: destination address. da = 0xFF -> broadcast message

        Returns return value of sendto call to socket.
        '''
        sa = self.my_sa
        spriority = (priority << 26) & 0x1C000000
        spgn      = (pgn      <<  8) & 0x03FFFF00
        ssa       = (sa       <<  0) & 0x000000FF

        
        data = bytearray(sdata)

        try:
            x = self.can_socket.sendto(data,(self.interface,socket.J1939_NO_NAME,pgn,da))
        except Exception as e:
            print(str(time.time())+" Send error: %s" % e)
            x=-1

        return x

    def read_message_raw(self):
        '''
        Return raw message data from CAN socket, including ancillary data and flags

        Returns tuple (data, ancdata, msgflags, address)
        '''
        try:
           data, ancdata, msgflags, address = self.can_socket.recvmsg(2048,64)
        except socket.timeout:
            return (None,None,None,None)
        except OSError:
            return (None,None,None,None)
        else:
            return (data,ancdata,msgflags,address)

    def read_message(self):
        '''
        Read message from bus.

        Returns tuple of (pgn, priority, src_addr, dst_addr, data). If message times out, all will be None.
        '''
        data,ancdata,msgflags,address = self.read_message_raw()
        pgn = None
        priority = None
        src_addr = None
        dst_addr = None
        
        if ancdata is not None and len(ancdata) == 1:
            priority = ancdata[0][2][0]
            dst_addr = 0xFF
        elif ancdata is not None and len(ancdata) == 2:
            priority = ancdata[1][2][0]
            dst_addr = ancdata[0][2][0]
        if address is not None:
            src_addr = address[4]
            pgn = address[3]
        return pgn,priority,src_addr,dst_addr,data

    def request_pgn(self,pgn, src_addr=0):
        '''
        Request PGN from a specified address.

        pgn: the PGN to request
        src_addr: address to request PGN from (should probably change to dst_address)

        Returns data, or None if timeout or problem.
        '''
        recvd = False
        start_time = time.time()
        req_data = bytes([pgn & 0xFF, (pgn & 0xFF00) >> 8, (pgn & 0xFF0000) >> 16])
        data = None
        while (not recvd) and time.time() - start_time < .5:
            sent_time = time.time()
            result = self.send_message(6,59904,req_data)
            if result < 0:
                continue
            (this_pgn,priority,src,dst,data) = self.read_message()
            while this_pgn != pgn and time.time() - sent_time < .2:
                (this_pgn,priority,src,dst,data) = self.read_message()
            if this_pgn == pgn and src == src_addr:
                recvd = True
            else:
                data = None
        
        return data

if __name__ == '__main__':
    driver = J1939Driver()
    names={'CompID':65259}
    for name in names.keys():
        print('%s (%d): %s' % (name,names[name],driver.request_pgn(names[name])))
        

