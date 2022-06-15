#!/usr/bin/env python3

# PLC4TRUCKSDuck (c) 2022 National Motor Freight Traffic Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# Theabove copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import time

import bitstring
import argparse

from hv_networks.J1587Driver import J1708DriverFactory, get_j1708_driver_factory
from hv_networks.J1708Driver import J1708Driver

parser = argparse.ArgumentParser(
    description="frame sending utility for J1708 and PLC on truckducks"
)
J1708DriverFactory.argparse(parser)
parser.add_argument(
    "hexbytes",
    help="a j1708 or plc message to send e.g. '0a00' or '0a,00' or '0a#00' or "
    + "'(123.123) j1708 0a#00'",
)
parser.add_argument(
    "--checksums",
    default="true",
    const="true",
    nargs="?",
    choices=["true", "false"],
    help="add checksums to frames sent",
)

args = parser.parse_args()
get_j1708_driver_factory().parse_args(args)


if __name__ == "__main__":
    hexinput = args.hexbytes.strip()
    hexinput = hexinput.split(";")[0]
    hexinput = hexinput.split(" ")[-1]
    hexinput = hexinput.replace(",", "")
    hexinput = hexinput.replace("#", "")
    message = bitstring.BitArray(hex=hexinput)
    if args.checksums == "true":
        message = J1708Driver.prepare_message(message, has_checksum=False)
    j1708_driver = get_j1708_driver_factory().make()
    j1708_driver.send_message(message.bytes, has_checksum=True)
    while True:
        if time.monotonic_ns() > j1708_driver.next_send_ns + 500000:
            break
