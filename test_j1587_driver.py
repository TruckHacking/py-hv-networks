import unittest

import struct
from hv_networks.J1708Driver import checksum
from hv_networks.J1587Driver import J1587Driver
from hv_networks.J1587Driver import J1708DriverFactory
from hv_networks.J1587Driver import set_j1708_driver_factory


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
            if checksum:
                return message
            else:
                return message[:-1]

    sent = list()

    def send_message(self, buf, has_check=False):
        msg = buf
        if not has_check:
            check = struct.pack('b', checksum(msg))
            msg += check
        self.sent.append(msg)

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

    def tearDown(self):
        self.fake_j1708_factory.clear()

    def test_one_send(self):
        driver = J1587Driver(0xac)
        self.assertIsNone(driver.send_message(b'\x00'))

    def test_one_receive(self):
        self.fake_j1708_factory.make().add_to_rx([b'\x00'])
        j1587_driver = J1587Driver(0xac)
        rx = j1587_driver.read_message(block=True, timeout=0.5)
        self.assertEqual(b'\x00', rx)


if __name__ == "__main__":
    unittest.main()
