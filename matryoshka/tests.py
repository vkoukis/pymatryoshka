#!/usr/bin/env python
#
# PyMatryoshka: A VXLAN-over-UDP agent
#
# Copyright (c) 2012 Vangelis Koukis <vkoukis@gmail.com>.
#
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


"""Unit tests for Matryoshka

Provides unit tests for the matryoshka server module.

"""

import os
import re
import subprocess
import sys
import time

SYSFS_NET = "/sys/class/net"

# Use backported unittest functionality if Python < 2.7
try:
    import unittest2 as unittest
except ImportError:
    if sys.version_info < (2, 7):
        raise Exception("The unittest2 package is required for Python < 2.7")
    import unittest

from IPy import IP
from vxlan import VXLAN
from tuntap import VirtualTap
from server import VirtualNetwork
from server import _mac_is_multicast, _ip_is_multicast
from scapy.layers.l2 import Ether


def _run_command(args):

    chld = subprocess.Popen(args,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    (stdout, stderr) = chld.communicate()
    ret = chld.wait()
    return (ret, stdout, stderr)


def _get_iface_attr(name, attr):
    f = file(os.path.join(SYSFS_NET, name, attr), "r")
    lines = f.readlines()
    return lines[0].strip()


def iface_exists(name):
    try:
        _get_iface_attr(name, "ifindex")
    except IOError:
        return False
    return True


def iface_mtu(name):
    return int(_get_iface_attr(name, "mtu"))


class IPTestCase(unittest.TestCase):
    def test_ipv4_is_multicast(self):
        self.assertFalse(_ip_is_multicast("147.102.3.1"))
        self.assertFalse(_ip_is_multicast("62.217.124.86"))
        self.assertTrue(_ip_is_multicast("224.0.1.2"))
        self.assertTrue(_ip_is_multicast("239.0.0.1"))

    def test_ipv6_is_multicast(self):
        self.assertFalse(_ip_is_multicast("2001:648:2ffc:106::86"))
        self.assertTrue(_ip_is_multicast("ff03:1234:abcd::1"))
        self.assertTrue(_ip_is_multicast("ff04::1"))


class MacTestCase(unittest.TestCase):
    def test_mac_is_multicast(self):
        self.assertFalse(_mac_is_multicast("10:01:02:03:04:05"))
        self.assertFalse(_mac_is_multicast("A6:01:02:03:04:05"))
        self.assertTrue(_mac_is_multicast("A7:01:02:03:04:05"))
        self.assertTrue(_mac_is_multicast("33:33:02:03:04:05"))


class VirtualTapTestCase(unittest.TestCase):
    def _tap_exists_ifconfig(self):
        (ret, stdout, stderr) = _run_command(["/sbin/ifconfig", self.tap.name])
        return ret == 0

    def _get_mtu_ifconfig(self):
        (ret, stdout, stderr) = _run_command(["/sbin/ifconfig", self.tap.name])
        self.assertEqual(stderr, "")
        self.assertEqual(ret, 0)
        remtu = re.compile("MTU:(\d+)+\ ")
        mtu = int(re.search(remtu, stdout).group(1))
        return mtu

    def setUp(self):
        self.tap = VirtualTap("testtap%d")

    def test_open_close_tap(self):
        self.tap.open()
        self.assertIsNotNone(self.tap.fd)
        self.assertEqual(self.tap.fd, self.tap.fileno())
        self.assertTrue(self.tap.name.startswith("testtap"))
        self.assertTrue(iface_exists(self.tap.name))
        self.tap.close()
        self.assertFalse(iface_exists(self.tap.name))

    def test_set_mtu(self):
        self.tap.open()
        self.assertGreater(iface_mtu(self.tap.name), 0)
        self.tap.set_mtu(1491)
        self.assertEqual(iface_mtu(self.tap.name), 1491)
        self.tap.close()


class VirtualNetworkTestCase(unittest.TestCase):
    MAC_TABLE_SIZE = 100
    MAC_TTL = 0.1

    def setUp(self):
        self.vnet = VirtualNetwork(vni=0xF0F1F2, macttl=self.MAC_TTL,
                                   mactablesize=100)

    def test_learn_mac(self):
        mac1 = "00:01:02:03:04:05"
        vtep1 = IP("127.0.0.1")
        mac2 = "05:04:03:02:01:00"
        vtep2 = IP("::1")
        self.assertTrue(self.vnet.learn(mac1, vtep1))
        self.assertTrue(self.vnet.learn(mac2, vtep2))
        self.assertEqual(self.vnet.lookup(mac1), vtep1)
        self.assertEqual(self.vnet.lookup(mac2), vtep2)

    def test_lookup_unknown_mac(self):
        mac1 = "00:01:02:0A:0B:0C"
        self.assertIsNone(self.vnet.lookup(mac1))

    def test_lookup_expired_mac(self):
        mac1 = "00:01:02:03:04:05"
        vtep1 = IP("127.0.0.1")
        self.assertTrue(self.vnet.learn(mac1, vtep1))
        self.assertEqual(self.vnet.lookup(mac1), vtep1)
        time.sleep(self.vnet.macttl)
        self.assertIsNone(self.vnet.lookup(mac1))

    def test_relearn_mac_updates_ttl(self):
        mac1 = "00:01:02:03:04:05"
        vtep1 = IP("127.0.0.1")
        vtep2 = IP("127.0.0.2")
        self.assertTrue(self.vnet.learn(mac1, vtep1))
        # Sleep just until the mac entry is about to expire
        time.sleep(self.vnet.macttl - 0.01)
        self.assertEqual(self.vnet.lookup(mac1), vtep1)
        self.assertFalse(self.vnet.learn(mac1, vtep2))
        # Make sure the ttl timer gets updated
        time.sleep(self.vnet.macttl - 0.01)
        self.assertEqual(self.vnet.lookup(mac1), vtep2)

    def _fill_mac_table(self, prefix, cnt):
        # Fill the MAC table so it's ready to overflow
        cur = len(self.vnet._macs)
        self.assertLessEqual(cur, cnt)
        for i in xrange(0, cnt - cur):
            m = "%s:%02X" % (prefix, i)
            self.assertTrue(self.vnet.learn(m, IP("127.0.0.1")))
        self.assertEqual(len(self.vnet._macs), cnt)

    def test_hit_mac_count_limit(self):
        """Test mac table detects overflow when size limit is reached"""
        self._fill_mac_table("DE:AD:BA:BE:00", self.MAC_TABLE_SIZE)
        m = "DE:AD:BA:BE:00:%02X" % (self.MAC_TABLE_SIZE + 1)
        self.assertRaises(MemoryError, self.vnet.learn, m, IP("127.0.0.1"))
        # Wait for the entries to expire
        time.sleep(self.vnet.macttl)
        self.assertTrue(self.vnet.learn(m, IP("127.0.0.1")))

    def test_gc(self):
        """Test gc only collects stale entries"""
        # Fill half the table
        self._fill_mac_table("DE:AD:BA:BE:00", self.MAC_TABLE_SIZE / 2)
        time.sleep(self.vnet.macttl - 0.01)
        # Make sure the entries are not collected
        self.vnet.gc()
        self.assertEqual(len(self.vnet._macs), self.MAC_TABLE_SIZE / 2)
        # Fill up table completely, and wait for the first half to expire
        self._fill_mac_table("DE:AD:BA:BE:01", self.MAC_TABLE_SIZE)
        time.sleep(self.vnet.macttl - 0.01)
        self.vnet.gc()
        self.assertEqual(len(self.vnet._macs), self.MAC_TABLE_SIZE / 2)
        # Then wait for the remaining entries to expire
        time.sleep(0.01)
        self.vnet.gc()
        self.assertFalse(len(self.vnet._macs))


class VXLANTestCase(unittest.TestCase):
    def test_from_frame(self):
        e = Ether(src='00:01:02:03:04:05', dst='AA:BB:CC:DD:EE:FF')
        e.add_payload("thisisapayload")
        frame = str(e)

        vx = VXLAN(frame=frame, vni=123)
        self.assertEqual(vx.vni, 123)
        self.assertEqual(str(vx),
            "\x08\x00\x00\x00\x00\x00\x7b\x00" + frame)

    def test_from_packet(self):
        e = Ether(src='00:01:02:03:04:05', dst='AA:BB:CC:DD:EE:FF')
        e.add_payload("thisisapayload")
        frame = str(e)

        packet = "\x08\x00\x00\x00\x00\x00\x7c\x00" + frame
        vx = VXLAN(packet=packet)
        self.assertEqual(vx.vni, 124)
        self.assertEqual(str(vx.frame), frame)
        self.assertEqual(str(vx), packet)
        self.assertEqual(vx.src_mac, "00:01:02:03:04:05")
        self.assertEqual(vx.dst_mac, "AA:BB:CC:DD:EE:FF")

if __name__ == "__main__":
    unittest.main()
