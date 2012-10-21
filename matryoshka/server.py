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


"""Matryoshka: A VXLAN-over-UDP agent"""

import daemon
import daemon.pidlockfile
import errno
import fcntl
import logging
import logging.handlers
import os
import pyinotify
import select
import socket
import struct
import sys
import time

from IPy import IP
#from scapy.layers.l2 import Ether
from signal import signal, siginterrupt, SIGTERM, SIGUSR1, SIGUSR2

from vxlan import VXLAN
from tuntap import VirtualTap

DEFAULT_MCASTIF = ""
DEFAULT_BINDADDR = ""
DEFAULT_BINDPORT = 3601
DEFAULT_STATEDIR = "/var/lib/matryoshka"
DEFAULT_LOGDIR = "/var/log/matryoshka"
DEFAULT_PIDFILE = "/var/run/matryoshka/matryoshka.pid"

LOG_FILENAME = "matryoshka.log"
LOG_FORMAT = "%(asctime)-15s %(levelname)-6s %(message)s"

DEFAULT_MAC_TABLE_SIZE = 10000


class FileHandler(pyinotify.ProcessEvent):
    """Handle pyinotify events from watching the state directory."""
    def __init__(self, server):
        pyinotify.ProcessEvent.__init__(self)
        self.server = server

    def process_IN_DELETE(self, event):
        """Handle deletion of file in the state directory.

        Whnever a file is deleted from the state directory,
        the server detaches itself from the associated virtual network.

        """

        logging.debug("File %s deleted, detaching from virtual network",
                      event.name)
        self.server.detach_from_network((os.path.join(event.path, event.name)))
        return

    def process_IN_CLOSE_WRITE(self, event):
        """Handle addition of file in the state directory.

        Whenever a file is added to the state directory,
        the server attaches itself to the associated virtual network.

        """
        logging.debug("File %s added, attaching to virtual network",
                      event.name)
        self.server.attach_to_network((os.path.join(event.path, event.name)))
        return


class VirtualNetwork(object):
    """A virtual network with MAC-to-VTEP learning functionality"""
    def __init__(self, vni, macttl, mactablesize=DEFAULT_MAC_TABLE_SIZE):
        self._macs = {}
        self.socket = None
        self.targetips = []

        self.vni = vni
        self.macttl = macttl
        self.mactablesize = mactablesize

        if not vni or not macttl:
            raise ValueError("vni and macttl arguments are mandatory")

    def __repr__(self):
        return "<vnet vni=0x%06X, macttl=%fs>" % (self.vni, self.macttl)

    def learn(self, mac, vtep):
        """Learn a new mac address on endpoint vtep.

        Learn a new mac address on endpoint vtep, return True
        if the mac address is a new entry, False if the mac
        address was already known, so the existing entry gets
        a refreshed ttl.

        """
        now = time.time()
        existing = mac in self._macs
        if not existing and len(self._macs) >= self.mactablesize:
            # Trigger cleaning of stale entries
            self.gc()
            if len(self._macs) >= self.mactablesize:
                raise MemoryError("Mac table size limit of %d reached for %r" %
                                  (self.mactablesize, self))

        self._macs[mac] = (vtep, now + self.macttl)
        return not existing

    def lookup(self, mac):
        """Lookup a MAC address, return VTEP if found, None otherwise"""
        now = time.time()
        entry = self._macs.get(mac, None)
        if not entry:
            return None
        if now > entry[1]:
            del self._macs[mac]  # Remove stale entry
            return None
        return entry[0]

    def gc(self):
        """Do garbage collection, flush all expired entries in MAC table"""
        now = time.time()
        for m in self._macs.keys():
            if now > self._macs[m][1]:
                del self._macs[m]


def _parse_network_file(path, family):
    """Read virtual network information from file"""
    try:
        ifile = open(path, "r")
    except IOError as ioe:
        logging.error("Unable to open network file %s: %s", path, ioe)
        return None

    try:
        vals = {}
        lcnt = 0
        for line in ifile:
            lcnt += 1
            # Lines are of the form "key = val", keys are converted
            # to all lowercase, lines starting with '#' are ignored.
            if not line.strip() or line.strip().startswith("#"):
                continue
            (key, val) = [s.strip() for s in line.strip().split("=", 1)]
            vals[key.lower()] = val
    except ValueError as ve:
        logging.error("Cannot parse line %d in %s using 'key=val' format: %s",
                      lcnt, path, ve)
        return None

    # Report on missing and unknown keys
    keys = ["tapname", "vni", "macttl", "targetip", "targetport"]
    unknown_keys = set(vals.keys()) - set(keys)
    missing_keys = set(keys) - set(vals.keys())
    if unknown_keys:
        logging.error("Unknown keys specified in network file %s: %s",
                      path, ", ".join(unknown_keys))
        return None
    if missing_keys:
        logging.error("Required keys missing from network file %s: %s",
                      path, ", ".join(missing_keys))
        return None

    try:
        vals["vni"] = int(vals["vni"])
        vals["macttl"] = float(vals["macttl"])
        targetip = IP(vals["targetip"])
        if (targetip.version() == 4 and family != socket.AF_INET or
            targetip.version() == 6 and family != socket.AF_INET6):
            msg = ("Cannot specify IPv%d IP in TARGETIP when"
                   " using %s") % (targetip.version(), _family_name(family))
            raise ValueError(msg)
        vals["targetip"] = str(targetip)
        vals["targetport"] = int(vals["targetport"])
    except ValueError as ve:
        logging.error("Validation failed for fields in %s: %s",
                      path, ve)
        return None

    if "tapname" in vals and vals["tapname"] != os.path.basename(path):
        logging.error("Network file %s refers to tap interface %s",
                      path, vals["tapname"])
        return None

    return vals


def _mac_is_multicast(mac):
    return int(mac.split(":")[0], 16) & 1 == 1


def _ip_is_multicast(ip):
    ip = IP(ip)
    if ip.version() == 4:
        return ip in IP("224.0.0.0/4")
    else:
        return ip in IP("ff00::/8")


def _family_name(family):
    d = {socket.AF_INET: "IPv4", socket.AF_INET6: "IPv6"}
    return d[family]


def _join_mcast_group(s, addr, ifname):
    logging.debug("Socket %s joining multicast group %s on ifname '%s'",
                  s.getsockname(), addr, ifname)

    # Set the TTL for outgoing IP multicast packets
    # A value of '1' means same subnet, see
    # http://tldp.org/HOWTO/Multicast-HOWTO-2.html.
    TTL = 1
    optval = struct.pack("@B", TTL)
    if s.family == socket.AF_INET:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, optval)
    else:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, optval)

    # Disable looping of locally originating packets
    LOOP = 0
    optval = struct.pack("@B", LOOP)
    if s.family == socket.AF_INET:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, optval)
    else:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, optval)

    # Subscribe the socket to the IP multicast group on interface ifname
    mcast_packed = socket.inet_pton(s.family, addr)
    if s.family == socket.AF_INET:
        optval = mcast_packed + struct.pack("!II", socket.INADDR_ANY,
                                            _if_nametoindex(ifname))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, optval)
    else:
        optval = mcast_packed + struct.pack("!I", _if_nametoindex(ifname))
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, optval)

    logging.debug("Socket %s joined multicast group %s on ifname '%s'",
                  s.getsockname(), addr, ifname)


def _leave_mcast_group(s, addr, ifname):
    logging.debug("Socket %s leaving multicast group %s on ifname '%s'",
                  s.getsockname(), addr, ifname)

    # Unsubscribe socket from the IP multicast group
    mcast_packed = socket.inet_pton(s.family, addr)
    if s.family == socket.AF_INET:
        optval = mcast_packed + struct.pack("!II", socket.INADDR_ANY,
                                            _if_nametoindex(ifname))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, optval)
    else:
        optval = mcast_packed + struct.pack("!I", _if_nametoindex(ifname))
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, optval)

    logging.debug("Socket %s left multicast group %s on ifname '%s'",
                  s.getsockname(), addr, ifname)


# Use ctypes to access libC's if_nametoindex().
# We need if_nametoindex() to get the network interface index
# to pass to IP_MULTICAST_IF/IPV6_MULTICAST_IF socket options.
from ctypes import CDLL
_libc = CDLL("libc.so.6")


def _if_nametoindex(ifname):
    if not ifname:
        return 0
    i = _libc.if_nametoindex(ifname)
    if not i:
        raise ValueError("Invalid network interface name %s" % ifname)
    return i


def _get_bound_udp_socket(family, addr, port, mcastif):
    """Get a UDP socket of the requested family.

    The socket is IPv4/IPv6 based on the value of family,
    bound to addr:port. If addr=None, the socket is bound to 0.0.0.0,
    or ::, for IPv4 and IPv6 respectively.

    If mcastif is set, outgoing multicast traffic is sent over the network
    interface with name mcastif on the local host, e.g. eth0.

    The socket is also set to allow IP broadcasting.

    """
    if not addr:
        addr = "0.0.0.0" if family == socket.AF_INET else "::"

    try:
        ip = IP(addr)
    except ValueError:
        logging.error("Not a valid IPv4 or IPv6 address: %s", addr)
        return None
    if (ip.version() == 4 and family != socket.AF_INET or
        ip.version() == 6 and family != socket.AF_INET6):
        logging.error("Cannot bind to an IPv%d address when using %s",
                      ip.version(), _family_name(family))
        return None

    try:
        s = socket.socket(family, socket.SOCK_DGRAM, 0)
        if family == socket.AF_INET6:
            # Only bind for IPv6 traffic when using an IPv6 socket
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((addr, port))
    except socket.error as msg:
        logging.error("Could not bind %s UDP socket on %s, port %d: %s",
                      _family_name(family), addr, port, msg)
        s.close()
        return None

    # Allow sending UDP datagrams to broadcast addresses
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception as msg:
        logging.error("Could not set the SO_BROADCAST flag on socket: %s",
                      msg)
        s.close()
        return None

    # Set the outgoing interface for multicast traffic
    try:
        ifindex = _if_nametoindex(mcastif)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                         struct.pack("!I", ifindex))
        else:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                         struct.pack("!III", 0, 0, ifindex))
    except Exception as msg:
        logging.error("Failed to set multicast interface to '%s': %s",
                      mcastif, msg)
        s.close()
        return None

    # Set the socket in non-blocking mode
    fcntl.fcntl(s, fcntl.F_SETFL, os.O_NONBLOCK)

    return s


def sigterm_handler(signum, stack_frame):
    assert signum == SIGTERM
    logging.info("Caught SIGTERM, terminating...")
    raise SystemExit


sigusr1_proxy = None
tracing = None


def sigusr12_handler(signum, stack_frame):
    global tracing
    assert signum == SIGUSR1 or signum == SIGUSR2
    if signum == SIGUSR1:
        logging.info("Caught SIGUSR1. Showing currnet proxy state:")
        sigusr1_proxy.log_state()
        return
    if signum == SIGUSR2:
        tracing = not tracing
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG if tracing else logging.INFO)
        logging.info("Caught SIGUSR2, %s tracing" %
                     ("enabling" if tracing else "disabling"))
        return


class VXLANProxy(object):
    """The main class implementing the Matryoshka VXLAN proxy."""
    def _create_vnet(self, vni, macttl):
        vn = VirtualNetwork(vni=vni, macttl=macttl)
        if vni in self.vnet_vni_map:
            raise ValueError("VNI %s already in use for vnet %r",
                self.vnet_vni_map[vni])
        self.vnet_vni_map[vni] = vn
        return vn

    def _vnet_from_vni(self, vni):
        return self.vnet_vni_map[vni]

    def _remove_vnet(self, vnet):
        msg = "Removed vnet %r" % vnet
        del self.vnet_vni_map[vnet.vni]
        del vnet
        logging.info(msg)

    def _attach_to_network(self, tapname, vni, macttl, targetip, targetport):
        if tapname in self.vnet_tapname_map:
            vnet = self.vnet_tapname_map[tapname]
            msg = ("Ignoring network addition request for tapname %s,"
                   " already in use for vnet %r" % (tapname, vnet))
            raise ValueError(msg)
        tap = VirtualTap(name=tapname)
        tap.open()
        self.taps.append(tap)
        # Set tap in non-blocking mode
        fcntl.fcntl(tap, fcntl.F_SETFL, os.O_NONBLOCK)

        vn = self._create_vnet(vni=vni, macttl=macttl)
        vn.targets = [(targetip, int(targetport))]
        vn.socket = self.socket
        vn.tap = tap
        tap.vnet = vn
        self.vnet_tapname_map[tapname] = vn

        for t in vn.targets:
            if _ip_is_multicast(t[0]):
                _join_mcast_group(vn.socket, t[0], self.mcastif)

        logging.info("Joined new network, vnet %r over tap %r",
                      tap.vnet, tap)

    def _detach_from_network(self, tapname):
        try:
            vnet = self.vnet_tapname_map[tapname]
        except KeyError:
            logging.error("Ignoring request to detach from unknown tap %s",
                          tapname)
            return

        for t in vnet.targets:
            if _ip_is_multicast(t[0]):
                _leave_mcast_group(vnet.socket, t[0], self.mcastif)

        del self.vnet_tapname_map[tapname]
        self._close_tap(vnet.tap)
        self._remove_vnet(vnet)

    def _close_tap(self, tap):
        logging.debug("Closing tap %r", tap)
        tap.close()
        self.taps.remove(tap)
        del tap

    def _handle_incoming_frame(self, tap):
        """Handle reception of incoming Ethernet frame on tap iface."""
        vnet = tap.vnet
        logging.debug("Incoming frame on tap %r, vnet %r", tap, vnet)
        frame = os.read(tap.fileno(), 10000)
        if not frame:
            logging.error("EOF on read, removing tap %r", tap)
            self._close_tap(tap)
            return

        # TODO: Learn source mac. If it's a new MAC,
        # broadcast the packet to all VTEPs, to force MAC table
        # update on migrations.

        # build VXLAN-encapsulated packet
        #ether = Ether(frame)
        #packet = VXLAN(VNI=vnet.vni) / ether
        vx = VXLAN(frame=frame, vni=vnet.vni)

        # lookup vtep address for target dst MAC,
        # broadcast to all known targets if it's a multicast MAC.
        targets = [None]
        if not _mac_is_multicast(vx.dst_mac):
            targets = [vnet.lookup(vx.dst_mac)]
        if targets[0] is None:
            targets = vnet.targets

        # send it over UDP
        # TODO: Hash ether's headers to get source UDP address
        s = vnet.socket
        for t in targets:
            buf = str(vx)
            logging.debug("Sending VXLAN packet of %d bytes to peer %s",
                          len(buf), t)
            # TODO: Set O_NONBLOCK everywhere, report EAGAIN errors
            s.sendto(buf, t)

    def _handle_incoming_packet(self, s):
        """Handle reception of encapsulated Ethernet frame on UDP socket."""
        logging.debug("Incoming packet on socket %s", s.getsockname())
        (packet, srcvtep) = s.recvfrom(10000)
        if not packet:
            logging.error("Received zero-length packet from %s?!", srcvtep)
            return
        logging.debug("Incoming packet of length %d from %s",
                      len(packet), srcvtep)
        try:
            # vxlan = VXLAN(packet)
            # vni = vxlan.VNI
            vx = VXLAN(packet=packet)
            vni = vx.vni
        except Exception as e:
            logging.error("Dropping malformed non-VXLAN packet: %s", e)
            return
        try:
            vnet = self._vnet_from_vni(vni)
        except KeyError:
            logging.error("Dropping packet with unknown VNI = %d", vni)
            return

        logging.debug("Incoming packet from %s, len = %d for vnet = %r",
                      srcvtep, len(packet), vnet)

        # ether = vxlan.getlayer(Ether)
        #logging.debug("Ether MACs: dst = %s, src = %s", ether.dst, ether.src)
        logging.debug("Ether MACs: dst = %s, src = %s", vx.dst_mac, vx.src_mac)
        if _mac_is_multicast(vx.src_mac):
            # Drop frames with multicast address as Ethernet source MAC.
            #
            # IEEE 802.3-2002, Section 3.2.3(b) says I/G (multicast) bit is
            # reserved for Ethernet src MACs, see
            # http://standards.ieee.org/getieee802/download/802.3-2002.pdf
            #
            # Also useful:
            # RFC 1812, Section 3.3.2 says a router MUST not believe any ARP
            # reply that claims that the Link Layer address of another host or
            # router is a broadcast or multicast address, but the MS load
            # balancer violates this rule.
            logging.warning("Dropping inner Ethernet frame with multicast src")
            return
        else:
            logging.debug("About to learn source MAC %s, endpoint %s",
                          vx.src_mac, srcvtep)
            try:
                wasnew = vnet.learn(vx.src_mac, srcvtep)
                logging.debug("MAC was %s for vnet %r",
                              'new' if wasnew else 'known', vnet)
            except MemoryError:
                logging.debug("Could not learn MAC, table for %r full",
                              vnet)
        try:
            logging.debug("Writing Ethernet frame of length %d to fd %d",
                          len(vx.frame), vnet.tap.fileno())
            # TODO: Set O_NONBLOCK everywhere
            n = os.write(vnet.tap.fileno(), vx.frame)
            if n != len(vx.frame):
                logging.warning("Short write: %d != %d to tap %r for vnet %r",
                                n, len(vx.frame), vnet.tap, vnet)
        except Exception as e:
            logging.error("Error writing frame to tap %r for vnet %r: %s",
                              vnet.tap, vnet, e)

    def __init__(self, family=socket.AF_INET,
                 bindaddr=DEFAULT_BINDADDR,
                 bindport=DEFAULT_BINDPORT,
                 mcastif=DEFAULT_MCASTIF,
                 statedir=DEFAULT_STATEDIR):
        self.taps = []
        self.sockets = []
        self.vnet_vni_map = {}
        self.vnet_tapname_map = {}

        self.family = family
        self.bindaddr = bindaddr
        self.bindport = bindport
        self.mcastif = mcastif
        self.statedir = statedir

        self.wm = pyinotify.WatchManager()
        mask = pyinotify.EventsCodes.ALL_FLAGS["IN_DELETE"]
        mask |= pyinotify.EventsCodes.ALL_FLAGS["IN_CLOSE_WRITE"]
        self.notifier = pyinotify.Notifier(self.wm, FileHandler(self))
        wdd = self.wm.add_watch(self.statedir, mask, rec=True)
        if wdd[self.statedir] < 0:
            raise Exception("Could not watch state directory %s" %
                            self.statedir)

        # Allocate a single listening UDP socket.
        self.socket = _get_bound_udp_socket(self.family,
                                            self.bindaddr, self.bindport,
                                            self.mcastif)
        if not self.socket:
            raise Exception("Could not get bound UDP socket")
        self.sockets.append(self.socket)

    def attach_to_network(self, path):
        """Attach to a new virtual network, get parameters from path.

        The basename of the path is used as the name of the tap interface
        used to attach to the virtual network on the local host.

        """
        logging.info("Attaching to network for file %s", path)
        tapname = os.path.basename(path)
        info = _parse_network_file(path, self.family)
        if not info:
            logging.error("Ignoring network file %s due to errors", path)
            return
        if tapname != info["tapname"]:
            raise ValueError("filename of %s does not match TAPNAME=%s" %
                             (tapname, info["tapname"]))
        self._attach_to_network(**info)

    def detach_from_network(self, path):
        """Detach from a virtual network.

        The basename of the path is used as the name of the tap interface
        used to determine which network to detach from.

        """
        logging.info("Detaching from network for file %s", path)
        tapname = os.path.basename(path)
        self._detach_from_network(tapname)

    def log_state(self):
        s = ["%s" % str(sock.getsockname()) for sock in self.sockets]
        t = ["%r %r" % (tap, tap.vnet) for tap in self.taps]
        logging.info("Current set of open sockets, %d entries: %s",
                     len(s), ", ".join(s))
        logging.info(("Current set of tap interfaces, and associated virtual"
                      " networks, %d entries: %s"), len(t),
                     ", ".join(t))
        logging.info("Current mapping of VNIs to virtual networks: %s",
                     repr(self.vnet_vni_map))
        logging.info(("Current mapping of tap interface names to virtual"
                      " networks: %s"), repr(self.vnet_tapname_map))
        logging.info("MAC tables per virtual network:")
        for v in self.vnet_vni_map.keys():
            vnet = self.vnet_vni_map[v]
            logging.info("vnet %r: %r", vnet, vnet._macs)

    def serve(self):
        # Cheat: get pyinotify Watch Manager's fd directly
        wmfd = self.wm._fd
        while True:
            # Before blocking on select(), process any pyinotify
            # events which may have been queued up by previous
            # invocations of serve(), but may have been left
            # unprocessed due to premature termination of this method,
            # if exceptions were thrown.
            logging.debug("processing any left-over pyinotify events")
            self.notifier.process_events()

            logging.debug("Waiting for input from %d sockets, %d taps",
                          len(self.sockets), len(self.taps))
            try:
                rdset = self.sockets + self.taps + [wmfd]
                rfds, wfds, excfds = select.select(rdset, [], [])
            except select.error as e:
                if e[0] == errno.EINTR:
                    continue

            logging.debug("Woke up after select, r = (%s, %s, %s)",
                          rfds, wfds, excfds)

            for fd in rfds:
                assert fd in rdset
            assert not wfds
            assert not excfds

            for fd in rfds:
                if fd in self.sockets:
                    logging.debug("Socket fd %d ready after select",
                                  fd.fileno())
                    self._handle_incoming_packet(fd)
                if fd in self.taps:
                    logging.debug("Tap fd %d ready after select",
                                  fd.fileno())
                    self._handle_incoming_frame(fd)
                if fd == wmfd:
                    self.notifier.read_events()
                    self.notifier.process_events()


def parse_arguments(args):
    from argparse import ArgumentParser, RawDescriptionHelpFormatter

    description = \
        ("Matryoshka is a VXLAN encapsulation agent, and implements a VXLAN\n"
         "Virtual Tunnel Endpoint (VTEP). It performs two main functions:\n"
         "a) it receives Ethernet frames from local tap ifaces, encapsulates\n"
         "   them in VXLAN packets with a proper Virtual Network ID (VNI), \n"
         "   and forwards them to the right VTEP based on destination MAC,\n"
         "b) it listens to a UDP port, receiving VXLAN-encapsulated Ethernet\n"
         "   frames, which it then forwards to the proper local tap device\n"
         "   based on the VNI of the incoming packet.\n\n"
         "Matryoshka watches a state directory for requests\n"
         "to attach and detach from virtual networks dynamically.")

    parser = ArgumentParser(description=description,
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--port", action="store", dest="bindport",
                        default=DEFAULT_BINDPORT, metavar="PORT",
                        help=("Bind to UDP port PORT, default is %d" %
                              DEFAULT_BINDPORT))
    parser.add_argument("-6", "--ipv6", action="store_const", dest="ipfamily",
                        default=socket.AF_INET, const=socket.AF_INET6,
                        help="Run over IPv6, default is to run over IPv4")
    parser.add_argument("-i", "--mcastif", action="store", dest="mcastif",
                        default=DEFAULT_MCASTIF, metavar="IFNAME",
                        help=("Send outgoing multicast datagrams, and join"
                              " multicast groups over the interface with name"
                              " IFNAME (e.g., eth0) on the local host. If not"
                              " specified, multicast traffic goes over the"
                              " default interface for the system."))
    parser.add_argument("--bindaddr", action="store", dest="bindaddr",
                        default=DEFAULT_BINDADDR, metavar="ADDRESS",
                        help=("Bind to host interface with address ADDRESS,"
                              " default is to bind to 0.0.0.0 or to ::, for"
                              " IPv4/IPv6 respectively. Warning: Do not bind"
                              " if you will be using broadcast or multicast"
                              " target addresses."))
    parser.add_argument("-s", "--statedir", action="store", dest="statedir",
                        default=DEFAULT_STATEDIR, metavar="DIRECTORY",
                        help=("Watch DIRECTORY for virtual network bindings,"
                              " default is %s" % DEFAULT_STATEDIR))
    parser.add_argument("--pidfile", action="store", dest="pidfile",
                        default=DEFAULT_PIDFILE, metavar="PIDFILE",
                        help=("Write the PID to PIDFILE if daemonizing,"
                              " default is %s" % DEFAULT_PIDFILE)),
    parser.add_argument("-d", "--debug", action="store_true", dest="debug",
                        default=False, help="Turn on debugging messages")
    parser.add_argument("-l", "--logging-dir", action="store", dest="logdir",
                        default=DEFAULT_LOGDIR, metavar="DIRECTORY",
                        help=("Store logfile %s in DIRECTORY, default is %s" %
                              (LOG_FILENAME, DEFAULT_LOGDIR)))
    parser.add_argument("-f", "--foreground", action="store_false",
                        dest="daemonize", default=True,
                        help="Stay in the foreground and do not daemonize")
    return parser.parse_args(args)


def main():
    global tracing
    opts = parse_arguments(sys.argv[1:])

    tracing = opts.debug
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if opts.debug else logging.INFO)
    if opts.daemonize:
        logfile = os.path.join(opts.logdir, LOG_FILENAME)
        handler = logging.handlers.RotatingFileHandler(logfile,
                                                       maxBytes=1048576)
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(handler)

    if opts.daemonize:
        pidfile = daemon.pidlockfile.TimeoutPIDLockFile(opts.pidfile, 10)
        d = daemon.DaemonContext(pidfile=pidfile,
                                 stdout=handler.stream, stderr=handler.stream,
                                 files_preserve=[handler.stream])
        d.umask = 0022
        d.open()

    logging.info("Starting matryoshka...")
    proxy = VXLANProxy(family=opts.ipfamily, bindaddr=opts.bindaddr,
                       bindport=opts.bindport, statedir=opts.statedir)

    # Touch every single file in state dir, to trigger additions
    logging.info("Touching all files under %s, to trigger network additions",
                 opts.statedir)
    try:
        for dirpath, dirnames, filenames in os.walk(opts.statedir):
            for fname in filenames:
                path = os.path.join(dirpath, fname)
                open(path, 'a').close()
    except Exception as msg:
        logging.error("Caught exception while touching files in %s: %s",
                      opts.statedir, msg)

    logging.info("Dropping privileges, setting capabilities, switching uid")
    # TODO: Drop all privileges

    # Handle SIGTERM, SIGUSR1, do not interrupt system calls
    global sigusr1_proxy
    sigusr1_proxy = proxy
    signal(SIGTERM, sigterm_handler)
    siginterrupt(SIGTERM, False)
    signal(SIGUSR1, sigusr12_handler)
    siginterrupt(SIGUSR1, False)
    signal(SIGUSR2, sigusr12_handler)
    siginterrupt(SIGUSR2, False)

    logging.info("Watching state directory %s", opts.statedir)

    while True:
        try:
            logging.info("Entering proxy request servicing loop")
            proxy.serve()
        except ValueError as ve:
            logging.error("Caught exception: Invalid input values: %s", ve)
            logging.info("Resuming main request loop")
        except Exception:
            logging.exception("Caught unexpected exception, text follows")
            logging.info("Resuming main request loop in 1s")
            time.sleep(1)

    logging.info("Exiting matryoshka...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
