#!/usr/bin/env python
#
# PyMatryoshka: A VXLAN-over-UDP agent
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


from fcntl import ioctl
import logging
import os
import socket
import struct

TUN_CLONE_DEVICE = "/dev/net/tun"
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

SIOCGIFMTU = 0x8921
SIOCSIFMTU = 0x8922


def _opentap(name):
    """Open a TAP device, clone it from /dev/net/tun.

    Create a new TAP device or open an existing one, name it based on the
    specified template, e.g. "mytap%d" or "mytap0". Return an (interface name,
    file descriptor) tuple.

    """

    tun = os.open(TUN_CLONE_DEVICE, os.O_RDWR)
    ifs = ioctl(tun, TUNSETIFF,
                struct.pack("@16sH", name, IFF_TAP | IFF_NO_PI))
    ifname = ifs[:16].strip("\x00")
    logging.debug("Allocated tap interface %s", ifname)
    return (ifname, tun)


def _set_if_mtu(ifname, mtu):
    """Set the MTU of any network interface, including that of a TAP device."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    ioctl(s, SIOCSIFMTU, struct.pack('@16sI', ifname, mtu) + '\x00' * 12)
    s.close()


class VirtualTap(object):
    """A Virtual TUN/TAP interface."""

    fd = None
    name = None

    def __init__(self, name="tap%d"):
        """Initialize a tap interface.

        Args:
            name: the template to use for naming the device,
                  May be generic, e.g. "tap%d", "mytap%d" to pick the
                  next available interface, or specific, e.g., "tap15".

        """
        self.name = name

    def __repr__(self):
        return "<tapfd %s [%s]>" % (self.fd, self.name)

    def open(self):
        """Operate on /dev/net/tun, open the underlying tap iface."""
        (name, fd) = _opentap(self.name)
        self.fd = fd
        self.name = name

    def close(self):
        """Close the underlying tap iface."""
        os.close(self.fd)

    def fileno(self):
        """Return the underling file descriptor.

        Return the file descriptor for the underlying tap iface.
        This allows VirtualTap objects to participate in select()/poll() calls.

        """
        return self.fd

    def set_mtu(self, mtu):
        """Set the MTU of the underlying tap iface."""
        _set_if_mtu(self.name, mtu)
