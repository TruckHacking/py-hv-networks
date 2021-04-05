import multiprocessing
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
        return

    to_rx = list()

    def add_to_rx(self, more_rx):
        self.to_rx.extend(more_rx)

    def read_message(self, checksum=False, timeout=0.5):
        if len(self.to_rx) == 0:
            return None
        else:
            message = self.to_rx.pop()
            if checksum:  # NB: J1587Drive will always call with checksums=true
                return message
            else:
                return message[:-1]

    sent = multiprocessing.Queue()

    def send_message(self, buf, has_check=False):
        msg = buf
        self.sent.put(msg)

    def close(self):
        return


class FakeJ1708Factory(J1708DriverFactory):
    def __init__(self):
        super(FakeJ1708Factory, self).__init__()
        self.memo_fake_driver = None

    def make(self):
        if self.memo_fake_driver is None:
            self.memo_fake_driver = FakeJ1708Driver()
        return self.memo_fake_driver

    def clear(self):
        self.memo_fake_driver = None


class J1587TestClass(unittest.TestCase):
    def setUp(self):
        self.fake_j1708_factory = FakeJ1708Factory()
        set_j1708_driver_factory(self.fake_j1708_factory)
        self.j1708_driver = self.fake_j1708_factory.make()

    def tearDown(self):
        self.fake_j1708_factory.clear()
        self.j1587_driver.cleanup()

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

    def test_fragment_not_receive(self):
        dummy = b'\x80\x00'
        rts_to_ac = b'\x80\xc5\x04\xac\x01\x01\x00\x01'
        self.j1708_driver.add_to_rx([rts_to_ac])
        self.j1708_driver.add_to_rx([dummy])
        self.j1587_driver = J1587Driver(0xac)
        rx = self.j1587_driver.read_message(block=True)
        self.assertEqual(dummy, rx)

    def test_fragment_receive(self):
        rts_to_ac = b'\x80\xc5\x04\xac\x01\x01\x00\x01'
        self.j1708_driver.add_to_rx([rts_to_ac])
        self.j1587_driver = J1587Driver(0xac, suppress_fragments=False)
        rx = self.j1587_driver.read_message(block=True)
        self.assertEqual(rts_to_ac, rx)

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


if __name__ == "__main__":
    unittest.main()
