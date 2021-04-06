import multiprocessing
import queue
import threading
import time
import unittest

import struct
from hv_networks.J1708Driver import checksum
from hv_networks.J1587Driver import J1587Driver
from hv_networks.J1587Driver import J1708DriverFactory
from hv_networks.J1587Driver import set_j1708_driver_factory
from hv_networks.J1587Driver import TimeoutException


# fake J1708Driver for testing
class FakeJ1708Driver:
    def __init__(self):
        self.to_rx = multiprocessing.Queue()
        self.sent = multiprocessing.Queue()
        self.stopped = threading.Event()
        return

    def add_to_rx(self, more_rx):
        for thing in more_rx:
            self.to_rx.put(thing)

    def read_message(self, checksum=False, timeout=0.5):
        if self.stopped.is_set():
            return None
        if self.to_rx.empty():
            return None
        else:
            message = self.to_rx.get()
            if checksum:  # NB: J1587Drive will always call with checksums=true
                return message
            else:
                return message[:-1]

    def send_message(self, buf, has_check=False):
        if self.stopped.is_set():
            return
        msg = buf
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
                self.memo_fake_driver = FakeJ1708Driver()
            a = self.memo_fake_driver
        return a

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
        rx = self.j1587_driver.read_message(block=True)
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
        rx = self.j1587_driver.read_message(block=True)
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
        rx = self.j1587_driver.read_message(block=True)
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


if __name__ == "__main__":
    unittest.main()
