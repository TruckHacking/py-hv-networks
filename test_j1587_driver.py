import multiprocessing
import queue
import threading
import time
import unittest

import struct
from hv_networks.J1708Driver import checksum, J1708Driver
from hv_networks.J1587Driver import J1587Driver
from hv_networks.J1587Driver import J1708DriverFactory
from hv_networks.J1587Driver import set_j1708_driver_factory
from hv_networks.J1587Driver import TimeoutException


# fake J1708Driver for testing
class FakeJ1708Driver:
    def __init__(self):
        self.to_rx = multiprocessing.Queue()
        self.to_respond = list()
        self.sent = multiprocessing.Queue()
        self.stopped = threading.Event()
        return

    def add_to_rx(self, more_rx):
        for thing in more_rx:
            self.to_rx.put(thing)

    def add_response(self, sent_trigger, response):
        self.to_respond.append((sent_trigger, response))

    def read_message(self, checksum=False, timeout=0.5):
        if self.stopped.is_set():
            return None
        if self.to_rx.empty():
            return None
        else:
            message = self.get_next_to_rx()
            if checksum:  # NB: J1587Driver will always call with checksums=true
                return J1708Driver.prepare_message(message, has_checksum=False)
            else:
                return message

    def get_next_to_rx(self):
        return self.to_rx.get()

    def send_message(self, buf, has_check=False):
        if self.stopped.is_set():
            return
        msg = buf
        if len(self.to_respond) > 0 and msg == self.to_respond[0][0]:
            self.add_to_rx([self.to_respond[0][1]])
            self.to_respond = self.to_respond[1:]
        self.sent.put(msg)

    def close(self):
        self.stopped.set()
        self.to_rx.close()
        self.sent.close()

    def __del__(self):
        self.close()


class FakeJ1708Factory(J1708DriverFactory):
    def __init__(self):
        self.a_lock = threading.Lock()
        with self.a_lock:
            self.memo_fake_driver = None
        super(FakeJ1708Factory, self).__init__()

    def make(self):
        with self.a_lock:
            if self.memo_fake_driver is None:
                self.memo_fake_driver = self.new_j1708_driver()
            a = self.memo_fake_driver
        return a

    def new_j1708_driver(self):
        return FakeJ1708Driver()

    def clear(self):
        with self.a_lock:
            self.memo_fake_driver = None


class J1587TestClass(unittest.TestCase):
    def setUp(self):  # ruddy naming b/c override from unittest.TestCase
        self.set_up()

    def tearDown(self):  # ruddy naming b/c override from unittest.TestCase
        self.tear_down()

    def set_up(self):
        self.fake_j1708_factory = FakeJ1708Factory()
        set_j1708_driver_factory(self.fake_j1708_factory)
        self.j1708_driver = self.fake_j1708_factory.make()

    def tear_down(self):
        self.j1587_driver.cleanup()
        self.fake_j1708_factory.clear()

    def test_no_receive(self):
        self.j1587_driver = J1587Driver(0xac)
        self.j1587_driver.send_message(b'\xff\x00')
        self.assertRaises(queue.Empty,
                          self.j1587_driver.read_message, block=True, timeout=1.0)

    def test_one_send(self):
        self.assertTrue(self.j1708_driver.sent.empty())
        self.j1587_driver = J1587Driver(0xac)
        self.j1587_driver.send_message(b'\xff\x00')
        self.assertEqual(b'\xff\x00', self.j1708_driver.sent.get(block=True, timeout=1.0))

    def test_one_send_trigger_response(self):
        self.assertTrue(self.j1708_driver.sent.empty())
        self.j1587_driver = J1587Driver(0xac)
        self.j1708_driver.add_response(b'\xff\x00', b'\x01\x01')
        self.j1587_driver.send_message(b'\xff\x00')
        self.assertEqual(b'\xff\x00', self.j1708_driver.sent.get(block=True, timeout=1.0))
        self.assertEqual(b'\x01\x01', self.j1587_driver.read_message(block=True, timeout=1.0))

    def test_one_send_with_loopback(self):
        self.assertTrue(self.j1708_driver.sent.empty())
        self.j1587_driver = J1587Driver(0xac, loopback=True)
        self.j1587_driver.send_message(b'\xff\x00')
        self.assertEqual(b'\xff\x00', self.j1708_driver.sent.get(block=True, timeout=1.0))
        self.assertEqual(b'\xff\x00', self.j1587_driver.read_message(block=True, timeout=1.0))

    def test_one_receive(self):
        self.j1708_driver.add_to_rx([b'\x80\x00'])
        self.j1587_driver = J1587Driver(0xac)
        rx = self.j1587_driver.read_message(block=True, timeout=5.0)
        # J1587Driver will receive broadcast, non-transport messages
        self.assertEqual(b'\x80\x00', rx)

    def test_fragment_for_us_not_read(self):
        rts_to_ac = b'\x80\xc5\x04\xac\x01\x01\x00\x01'
        dummy = b'\x80\x00'
        self.j1708_driver.add_to_rx([rts_to_ac])
        self.j1708_driver.add_to_rx([dummy])

        self.assertTrue(self.j1708_driver.sent.empty())
        self.j1587_driver = J1587Driver(0xac)
        rx = self.j1587_driver.read_message(block=True, timeout=7.0)
        self.assertEqual(dummy, rx)
        # confirm that the driver sends a CTS in response to the RTS
        self.assertEqual(b'\xac\xc5\x04\x80\x02\x01\x01', self.j1708_driver.sent.get(block=True, timeout=1.0))

    def test_fragment_for_other_not_read(self):
        rts_to_ac = b'\x80\xc5\x04\xac\x01\x01\x00\x01'
        dummy = b'\x80\x00'
        self.j1708_driver.add_to_rx([rts_to_ac])
        self.j1708_driver.add_to_rx([dummy])

        self.assertTrue(self.j1708_driver.sent.empty())
        self.j1587_driver = J1587Driver(0xb6)
        rx = self.j1587_driver.read_message(block=True, timeout=7.0)
        self.assertEqual(dummy, rx)
        # confirm that the driver does not send a CTS in response to the RTS
        self.assertRaises(queue.Empty,
                          self.j1708_driver.sent.get, block=True, timeout=1.0)

    def test_fragment_receive(self):
        rts_to_ac = b'\x80\xc5\x04\xac\x01\x01\x00\x01'
        self.j1708_driver.add_to_rx([rts_to_ac])
        self.j1587_driver = J1587Driver(0xac, suppress_fragments=False)
        rx = self.j1587_driver.read_message(block=True)
        self.assertEqual(rts_to_ac, rx)
        # confirm that the driver sends a CTS in response to the RTS
        self.assertEqual(b'\xac\xc5\x04\x80\x02\x01\x01', self.j1708_driver.sent.get(block=True, timeout=1.0))

    def test_fragment_receive_but_silent(self):
        rts_to_ac = b'\x80\xc5\x04\xac\x01\x01\x00\x01'
        self.j1708_driver.add_to_rx([rts_to_ac])
        self.j1587_driver = J1587Driver(0xac, suppress_fragments=False, silent=True)
        rx = self.j1587_driver.read_message(block=True)
        self.assertEqual(rts_to_ac, rx)
        # confirm that the driver does not send a CTS in response to the RTS
        self.assertRaises(queue.Empty,
                          self.j1708_driver.sent.get, block=True, timeout=1.0)

    def test_send_cts_waiting(self):
        self.assertTrue(self.j1708_driver.sent.empty())
        self.j1587_driver = J1587Driver(0xac)
        self.assertRaises(TimeoutException,
                          self.j1587_driver.transport_send, 0x80, b'\x00\xc8\x07\x04\x06\x00\x46\x41\x41\x5a\x05\x48'
                          )  # times out because there's no responding node

    def test_send_cts_preempt(self):
        self.assertTrue(self.j1708_driver.sent.empty())
        self.j1587_driver = J1587Driver(0xac, preempt_cts=True)
        self.j1587_driver.transport_send(0x80, b'\x00\xc8\x07\x04\x06\x00\x46\x41\x41\x5a\x05\x48')
        self.assertEqual(b'\xac\xc5\x05\x80\x01\x01\x0c\x00', self.j1708_driver.sent.get(block=True, timeout=1.0))
        self.assertEqual(b'\xac\xc6\x0e\x80\x01\x00\xc8\x07\x04\x06\x00\x46\x41\x41\x5a\x05\x48', self.j1708_driver.sent.get(block=True, timeout=1.0))
        self.assertTrue(self.j1708_driver.sent.empty())

    def test_receive_reassemble_for_us(self):
        self.j1708_driver.add_to_rx([b'\xac\xc5\x05\x80\x01\x01\x0c\x00'])
        self.j1708_driver.add_to_rx([b'\xac\xc6\x0e\x80\x01\x00\xc8\x07\x04\x06\x00\x46\x41\x41\x5a\x05\x48'])
        self.j1587_driver = J1587Driver(0x80)
        rx = self.j1587_driver.read_message(block=True, timeout=7.0)
        self.assertEqual(b'\xac\x00\xc8\x07\x04\x06\x00\x46\x41\x41\x5a\x05\x48', rx)

    def test_receive_dont_reassemble_one_for_others(self):
        self.j1708_driver.add_to_rx([b'\xac\xc5\x05\x80\x01\x01\x0c\x00'])
        self.j1708_driver.add_to_rx([b'\xac\xc6\x0e\x80\x01\x00\xc8\x07\x04\x06\x00\x46\x41\x41\x5a\x05\x48'])
        self.j1587_driver = J1587Driver(0xb6)
        self.assertRaises(queue.Empty,
                          self.j1587_driver.read_message, block=True, timeout=1.0)

    def test_receive_reassemble_one_for_others(self):
        self.j1708_driver.add_to_rx([b'\xac\xc5\x05\x80\x01\x01\x0c\x00'])
        self.j1708_driver.add_to_rx([b'\xac\xc6\x0e\x80\x01\x00\xc8\x07\x04\x06\x00\x46\x41\x41\x5a\x05\x48'])
        self.j1587_driver = J1587Driver(0xb6, reassemble_others=True)
        rx = self.j1587_driver.read_message(block=True, timeout=1.0)
        self.assertEqual(b'\xac\x00\xc8\x07\x04\x06\x00\x46\x41\x41\x5a\x05\x48', rx)
        self.assertRaises(queue.Empty,
                          self.j1587_driver.read_message, block=True, timeout=1.0)

    def test_receive_reassemble_multisection_component_id(self):
        self.j1708_driver.add_to_rx([
                                    bytes([0x80, 192, 17, 243, 32, 33,
                                           0x80,
                                           0x43, 0x43, 0x43, 0x43, 0x43, 0x2a,
                                           0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44
                                           ]),
                                    bytes([0x80, 192, 17, 243, 33,
                                           0x44, 0x44, 0x44, 0x2a,
                                           0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56,
                                           ]),
                                    bytes([0x80, 192,  6, 243, 34,
                                           0x56, 0x56, 0x56, 0x56])
                                    ])

        self.j1587_driver = J1587Driver(0xb6, reassemble_others=True)
        rx = self.j1587_driver.read_message(block=True, timeout=1.0)
        self.assertEqual(bytes([0x80, 243,
                                0x21,
                                0x80, 0x43, 0x43, 0x43, 0x43, 0x43, 0x2a,
                                0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x2a,
                                0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56, 0x56
                                ]), rx)
        self.assertRaises(queue.Empty,
                          self.j1587_driver.read_message, block=True, timeout=1.0)

    def test_receive_reassemble_multisection_diagnostic_code(self):
        self.j1708_driver.add_to_rx([
                                    bytes([0x88, 192, 0x0f, 194, 0x10, 0x15,
                                           0x6,
                                           0xb5, 0x0f, 0x05, 0xb5, 0x0f, 0x04, 0xb5, 0x0f, 0x03, 0xb5, 0x0f]),
                                    bytes([0x88, 192, 0x0b, 194, 0x11,
                                           0x01, 0xb5, 0x0f, 0x02, 0xb5, 0x0f, 0xfd, 0xb2, 0x11])
                                    ])

        self.j1587_driver = J1587Driver(0xb6, reassemble_others=True)
        rx = self.j1587_driver.read_message(block=True, timeout=1.0)
        self.assertEqual(bytes([0x88, 194,
                                21,
                                0x6, 0xb5, 0x0f, 0x05, 0xb5, 0x0f, 0x04, 0xb5, 0x0f, 0x03, 0xb5, 0x0f,
                                0x01, 0xb5, 0x0f, 0x02, 0xb5, 0x0f, 0xfd, 0xb2, 0x11
                                ]), rx)
        self.assertRaises(queue.Empty,
                          self.j1587_driver.read_message, block=True, timeout=1.0)

    def test_j1587_send_no_dropping(self):
        self.j1587_driver = J1587Driver(0xac, silent=True)

        count = 2048
        for i in range(count):
            self.j1587_driver.send_message(b'\x01\x02\x03\x04')

        now = time.monotonic()
        sent = list()
        while len(sent) < count:
            if time.monotonic() - now > 1.5 * count / 100.0:
                break
            sent.append(self.j1708_driver.sent.get())
        self.assertEqual(count, len(sent))


if __name__ == "__main__":
    unittest.main()
