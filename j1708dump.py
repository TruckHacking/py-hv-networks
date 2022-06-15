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
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import bitstring
import argparse
import sys
import time
import functools
from scapy.all import UDP, AsyncSniffer
import queue

from hv_networks.J1587Driver import J1708DriverFactory, get_j1708_driver_factory
from hv_networks.J1708Driver import J1708Driver

print = functools.partial(print, flush=True)

parser = argparse.ArgumentParser(
    description="frame dumping utility for J1708 and PLC on truckducks"
)
J1708DriverFactory.argparse(parser)
parser.add_argument(
    "--show-checksums",
    default="false",
    const="true",
    nargs="?",
    choices=["true", "false"],
    help="show frame checksums",
)
parser.add_argument(
    "--validate",
    default="true",
    const="true",
    nargs="?",
    choices=["true", "false"],
    help="discard frames with invalid checksums",
)
parser.add_argument(
    "--show",
    nargs="?",
    action="append",
    help="specify a candump-like filter; frames matching this filter will be shown. Processed before"
    + 'hide filters. e.g. "ac:ff" to show only MID 0xAC frames',
)
parser.add_argument(
    "--hide",
    nargs="?",
    action="append",
    help='specify a candump-like filter; frames matching this filter will be hidden. e.g. "89:ff" to'
    + "hide MID 0x89 frames",
)
parser.add_argument(
    "--promiscuous",
    "-P",
    action="store_true",
    help="perform j1708 capture in promiscuous mode, dumps without interfering with other j1708"
    + "consumers, requires priveleges (probably root) and works only on truckducks",
)

args = parser.parse_args()
get_j1708_driver_factory().parse_args(args)


def get_filter_val_and_mask(phil):
    philsplit = phil.split(":")
    val = philsplit[0]
    if len(philsplit) < 2:
        mask = "f" * len(val)
    else:
        mask = philsplit[1]
    return val, mask


def is_filter_applies(phil, messagebits):
    (val, mask) = get_filter_val_and_mask(phil)
    mask = bitstring.ConstBitArray(hex=mask)
    masklen = mask.len
    testmessage = messagebits[:masklen]
    return (testmessage & mask[: testmessage.len]).hex == val


j1708_driver: J1708Driver
q: queue.Queue
skip = 0  # loopback interface duplicates packets, need to skip every second one
scapy_thread: AsyncSniffer
scapy_thread = None


def init_source():
    global j1708_driver
    global scapy_thread
    global q
    j1708_driver = get_j1708_driver_factory().make()
    if args.promiscuous:
        q = queue.Queue()

        def doit(x):
            global skip
            if skip == 0:
                q.put(x.load)
                skip = 1
            else:
                skip = 0

        scapy_thread = AsyncSniffer(
            iface="lo", filter="udp port %s" % j1708_driver.clientport, prn=doit
        )
        scapy_thread.start()


def get_one_message():
    global j1708_driver
    global q
    if args.promiscuous:
        return q.get()
    else:
        msg = None
        while msg is None:
            msg = j1708_driver.read_message(checksum=True)
        return msg


def main():
    init_source()
    while True:
        message = get_one_message()

        skip_this_message = False
        messagebits = None

        if not args.show is None:
            skip_this_message = True

            if messagebits is None:
                messagebits = bitstring.ConstBitArray(message)
            for phil in args.show:
                if is_filter_applies(phil, messagebits):
                    skip_this_message = False
                    break

        if args.hide is not None:
            if messagebits is None:
                messagebits = bitstring.ConstBitArray(message)
            for phil in args.hide:
                if is_filter_applies(phil, messagebits):
                    skip_this_message = True
                    break

        if skip_this_message:
            continue

        if messagebits is None:
            messagebits = bitstring.ConstBitArray(message)
        if messagebits.len < 8:
            sys.stderr.write('short frame "%s"\n' % messagebits)
            continue

        comment = ""
        test_checksum = J1708Driver.prepare_message(message[:-1], has_checksum=False)[
            -1
        ]
        if test_checksum != message[-1]:
            if args.validate == "true":
                continue
            else:
                comment = "; invalid checksum"

        if args.show_checksums == "false":
            message = message[:-1]
        print(
            "(%.6f) %s %s %s"
            % (time.monotonic(), args.j1708_interface, message.hex(), comment)
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    if scapy_thread is not None:
        scapy_thread.stop()
        scapy_thread = None
    sys.exit()
