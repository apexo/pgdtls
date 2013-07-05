#!/usr/bin/python

import socket
import select
import argparse
import re
import sys
import subprocess

from gnutls_common import GNUTLSError
from gnutls_const import GNUTLS_E_LARGE_PACKET, GNUTLS_E_MEMORY_ERROR
from gnutls_ffi import lib
from gnutls import PSKClientCredentials, Priority, PSKServerCredentials
from dtlstest import DTLSSocket, NotConnected, HandshakeInProgress
from reactor import Reactor
from util import log
from sockmsg import addrtuple_to_name, MMsgHdr, name_to_addrtuple
from tuntap import TUNTAP
from functools import partial

class Callback(object):
	def __init__(self, tap, autoConnect):
		self.tap = tap
		self.autoConnect = autoConnect
		self.connections = []

	def handshake(self, conn):
		log("handshake: %r" % (conn,))
		if conn in self.connections:
			self.connections.remove(conn)

	def connected(self, conn):
		log("connected: %r" % (conn,))
		if conn not in self.connections:
			self.connections.append(conn)

	def recvfrom(self, data, data_len, seq, conn):
		self.tap.write(data, data_len)

	def gone(self, conn):
		log("gone: %r" % (conn,))
		if conn in self.connections:
			self.connections.remove(conn)
		if conn.name in self.autoConnect:
			conn.sock.connect(conn.name)

def sendmsg(fd, msg):
	#print("SENDMSG %r(%r) to %r" % (msg, msg.msg_iov[0].iov_len, name_to_addrtuple(ffi.buffer(msg.msg_name, msg.msg_namelen)[:])))
	res = lib.sendmsg(fd, msg, 0)
	if res < 0:
		log("SENDMSG(%d, %r, 0) = %d" % (fd, msg, res))
	return res

def recvmmsg(events, dsock, fd, mmsg):
	n = mmsg.recv(fd)
	if n > 0:
		for i in range(n):
			#print("RECVMSG %r" % (mmsg.msgvec[i].msg_len,))
			dsock.recvmsg(mmsg.iov[i].iov_base, mmsg.msgvec[i].msg_len, mmsg.name + i, mmsg.msgvec[i].msg_hdr.msg_namelen)
		mmsg.reinit(n)
	elif n < 0:
		log("RECVMMSG(%d, %r, 0) = %d" % (fd, n))
	else:
		raise Exception("EOF")

def read(events, dsock, tap, connections):
	n = tap.read()
	if not n:
		raise Exception("read 0 from tap")
	try:
		connections[0].send(tap.buf, n)
	except (NotConnected, HandshakeInProgress, IndexError):
		log("discarding message - not connected")
	except GNUTLSError as e:
		if e.errno in (GNUTLS_E_LARGE_PACKET, GNUTLS_E_MEMORY_ERROR):
			# TODO: should maybe fragment packet or return ICMP?
			pass
		else:
			raise

def port(v):
	p = int(v)
	if not 0 <= p <= 65535:
		raise ValueError(p)
	return p

def host_port(v,
	v4num=re.compile(r"^(\d+(?:\.\d+){3}):([0-9]{1,5})$"),
	v6num=re.compile(r"^\[([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}|[0-9a-fA-F:]*::[0-9a-fA-F:.]*)\]:([0-9]{1,5})$"),
	named=re.compile(r"^((?:(?:[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?)\.)*(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?)):([0-9]{1,5})$"),
):
	for (af, cre) in ((socket.AF_INET6, v6num), (socket.AF_INET, v4num)):
		m = cre.match(v)
		if m:
			try:
				socket.inet_pton(af, m.group(1))
				return v, [(af, socket.SOCK_DGRAM, socket.IPPROTO_UDP, '', (m.group(1), port(m.group(2))))]
			except (socket.error, ValueError):
				pass

	m = named.match(v)
	if m:
		try:
			p = port(m.group(2))
			result = []
			for af in (socket.AF_INET6, socket.AF_INET):
				try:
					result += socket.getaddrinfo(m.group(1), p, af, socket.SOCK_DGRAM)
				except socket.gaierror:
					pass
			if not result:
				raise ValueError("host %s cannot be resolved" % (m.group(1),))
			return v, result
		except ValueError:
			pass

	raise ValueError("illegal host/port: %s" % (v,))

def select_autoconnect_names(args):
	want_v4 = args.af.index(socket.AF_INET) if socket.AF_INET in args.af else -1
	want_v6 = args.af.index(socket.AF_INET6) if socket.AF_INET6 in args.af else -1
	if want_v4 >= 0:
		if want_v6 == -1:
			filter_ = lambda addrinfo_list: [addrinfo for addrinfo in addrinfo_list if addrinfo[0] == socket.AF_INET]
			filter_name = "IPv4"
		# both -4 and -6 specified: sort list based on preference (we assume that the option specified first has higher priority)
		elif want_v4 < want_v6:
			filter_ = lambda addrinfo_list: sorted(addrinfo_list, key=lambda addrinfo: addrinfo[0] == socket.AF_INET6)
		else:
			filter_ = lambda addrinfo_list: sorted(addrinfo_list, key=lambda addrinfo: addrinfo[0] == socket.AF_INET)
	else:
		filter_ = lambda addrinfo_list: [addrinfo for addrinfo in addrinfo_list if addrinfo[0] == socket.AF_INET6]
		filter_name = "IPv6"

	error = False
	result = []

	for host, addrinfo_list in args.autoConnect or ():
		addrinfo_list[:] = filter_(addrinfo_list)
		if not addrinfo_list:
			log("cannot connect to %s with %s" % (host, filter_name))
			error = True
		else:
			ai = addrinfo_list[0]
			if want_v6 >= 0 and ai[0] == socket.AF_INET:
				# we'll be using an IPv6 socket to contact an IPv4 host, embed IPv4 in v6 address with ::ffff:/96 prefix
				result.append(addrtuple_to_name(socket.AF_INET6, ("::ffff:" + ai[4][0], ai[4][1], 0, 0)))
			else:
				result.append(addrtuple_to_name(ai[0], ai[4]))

	if error:
		raise SystemExit(1)
	return result

if sys.version_info.major == 3:
	import binascii
	def bytes_type(v):
		return bytes(v, "UTF-8")
	def hex_type(v):
		return binascii.unhexlify(bytes(v, "ascii"))
else:
	bytes_type = str
	def hex_type(v):
		return v.decode("hex")

def parse_arguments():
	ap = argparse.ArgumentParser()
	ap.add_argument("-4", dest="af", action="append_const", const=socket.AF_INET)
	ap.add_argument("-6", dest="af", action="append_const", const=socket.AF_INET6)
	ap.add_argument("-c", "--connect", metavar="hostport", dest="autoConnect", action="append", type=host_port)
	ap.add_argument("-u", "--psk-username", action="store", type=bytes_type)
	ap.add_argument("-p", "--psk-password", action="store", type=hex_type)
	ap.add_argument("-f", "--psk-file", action="store", type=bytes_type)
	ap.add_argument("-l", "--listen-port", action="store", type=port, default="0")
	ap.add_argument("-P", "--priority", action="store", default="SECURE192:+PSK", type=bytes_type)
	ap.add_argument("--up", action="store", help="script to invoke for configuring the interface")
	args = ap.parse_args()
	args.af = args.af or [socket.AF_INET, socket.AF_INET6] # if neither -4 nor -6 is specified: use both, prefer IPv4
	args.autoConnect = select_autoconnect_names(args)
	return args

def up(args, tap):
	if not args.up:
		return

	connect = []
	for name in args.autoConnect:
		addr = name_to_addrtuple(name)
		if addr[0].startswith("::ffff:"):
			connect.append(addr[0][7:])
		else:
			connect.append(addr[0])
		connect.append(str(addr[1]))

	rc = subprocess.Popen([args.up] + connect, env={"DEVICE_NAME": tap.name}).wait()
	if rc:
		log("error invoking up script: %d" % (rc,))

def main():
	args = parse_arguments()

	af = socket.AF_INET6 if socket.AF_INET6 in args.af else socket.AF_INET
	s = socket.socket(af, socket.SOCK_DGRAM)
	if args.listen_port:
		listen_host = "0.0.0.0" if af == socket.AF_INET else "::"
		s.bind((listen_host, args.listen_port))

	if args.psk_username and args.psk_password:
		clientCredentials = PSKClientCredentials()
		clientCredentials.set(args.psk_username, args.psk_password)
	else:
		clientCredentials = None

	if args.psk_file:
		serverCredentials = PSKServerCredentials()
		serverCredentials.setFile(args.psk_file)
	else:
		serverCredentials = None

	priority = Priority(args.priority)

	tap = TUNTAP()
	tap.init(False)
	tap.setMTU(1149)
	print("/dev/%s" % (tap.name,))
	up(args, tap)

	cb = Callback(tap, args.autoConnect)

	reactor = Reactor()
	dsock = DTLSSocket(cb, partial(sendmsg, s.fileno()), reactor, priority, clientCredentials, serverCredentials)
	reactor.register(s.fileno(), select.EPOLLIN, recvmmsg, dsock, s.fileno(), MMsgHdr())
	reactor.register(tap.fd, select.EPOLLIN, read, dsock, tap, cb.connections)
	for name in args.autoConnect:
		dsock.connect(name)
	reactor.run()

if __name__ == '__main__':
	main()
