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


"""Define VXLAN packet classes"""

import struct

from scapy.layers.l2 import Ether
from scapy.fields import XByteField, X3BytesField
from scapy.packet import Packet, bind_layers


class scapy_VXLAN(Packet):
    name = "VXLAN"
    fields_desc = [XByteField("flags", 0b00001000),
                   X3BytesField("Reserved1", 0),
                   X3BytesField("VNI", 0),
                   XByteField("Reserved2", 0)]

# VXLAN packets encapsulate Ethernet frames
bind_layers(scapy_VXLAN, Ether, )


# This class should be rewritten with bytearray and memoryview objects,
# not supported in Python 2.6.
class VXLAN(object):
    """A class describing a VXLAN packet"""
    def from_packet(self, packet):
        """Construct a VXLAN packet from dissection of a given packet"""
        if len(packet) <= 8:
            raise ValueError("packet is smaller than VXLAN header length of 8")
        if packet[0:4] != "\x08\x00\x00\x00":
            raise ValueError("packet flags not 0x08 or Reserved1 not zero")
        if packet[7] != "\x00":
            raise ValueError("packet Reserved2 not zero")
        self._vni = struct.unpack("!I", "\x00" + packet[4:7])[0]
        self.frame = buffer(packet, 8)

    def from_frame(self, frame, vni=None):
        """Construct a VXLAN packet from an Ethernet frame for the given VNI"""
        if vni is not None:
            self._setvni(vni)
        self.frame = buffer(frame)

    def __init__(self, *args, **kwargs):
        frame = kwargs.get("frame", None)
        packet = kwargs.get("packet", None)
        vni = kwargs.get("vni", None)
        if args:
            raise ValueError("only keyword arguments supported")
        if ((frame is None and packet is None) or
            (frame is not None and packet is not None)):
                msg = "Exactly one of 'frame' or 'packet' must be specified"
                raise ValueError(msg)

        self._vni = vni

        if frame:
            self.from_frame(frame, vni)
        if packet:
            self.from_packet(packet)

    def __str__(self):
        """Return a string representation of the VXLAN packet"""
        self._validate()
        packet = "\x08\x00\x00\x00" + struct.pack("!I", self._vni)[1:] + "\x00"
        packet += str(self.frame)

        return packet

    def _getvni(self):
        return self._vni

    def _setvni(self, vni):
        vni = int(vni)
        if vni < 0 or vni >> 24:
            raise ValueError("vni must be non-negative and fit in 24 bits")
        self._vni = vni

    vni = property(_getvni, _setvni, None,
                   "Virtual Network Identifier (VNI) field")

    def _validate(self):
        """Ensure this is a valid VXLAN packet, with a frame of >= 12 bytes"""
        if self._vni is None:
            raise ValueError("VXLAN packet has no VNI set")
        if len(self.frame) < 12:
            raise ValueError("Inner Ethernet frame is shorter than 12 bytes")

    # Peek into the Ethernet frame
    @property
    def src_mac(self):
        self._validate()
        return ":".join(["%02X" % ord(c) for c in self.frame[6:12]])

    @property
    def dst_mac(self):
        return ":".join(["%02X" % ord(c) for c in self.frame[0:6]])
