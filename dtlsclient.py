import socket
import select

from pgdtls.ffi import ffi, lib
from pgdtls import PSKClientCredentials, Priority
from pgdtls.dtls import DTLSSocket, NotConnected, HandshakeInProgress
from pgdtls.reactor import Reactor, clock
from pgdtls.util import log
from pgdtls.sockutil import addrtuple_to_name, MMsgHdr

INTERVAL = 1
NAME = addrtuple_to_name(socket.AF_INET6, ("::1", 11111))
PAYLOAD = b"hi"*580
PAYLOAD_BUFFER = ffi.new("unsigned char[]", PAYLOAD)
PAYLOAD_SIZE = len(PAYLOAD)

stat = [0, 0, clock()]
last = list(stat)

class Callback(object):
	def handshake(self, conn):
		log("handshake: %r" % (conn,))

	def connected(self, conn):
		log("connected: %r" % (conn,))

	def recvfrom(self, data, data_len, seq, conn):
		stat[1] += data_len
		#log("recvfrom: %r %r %r %r" % (data, seq, sock, peer))

	def gone(self, conn):
		log("gone: %r" % (conn,))

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

reactor = Reactor()

credentials = PSKClientCredentials()
credentials.set(b"user", b"password")

priority = Priority(b"SECURE192:+PSK")

def sendmsg(msg, fd=s.fileno()):
	res = lib.sendmsg(fd, msg, 0)
	if res < 0:
		log("SENDMSG(%d, %r, 0) = %d" % (fd, msg, res))
	return res

dsock = DTLSSocket(Callback(), sendmsg, reactor, priority, credentials, None)

def recvmmsg(events, s, dsock, fd=s.fileno(), mmsg=MMsgHdr()):
	n = mmsg.recv(fd)
	if n > 0:
		for i in range(n):
			dsock.recvmsg(mmsg.iov[i].iov_base, mmsg.msgvec[i].msg_len, mmsg.name + i, mmsg.msgvec[i].msg_hdr.msg_namelen)
		mmsg.reinit(n)
	elif n < 0:
		log("RECVMMSG(%d, %r, 0) = %d" % (fd, n))
	else:
		raise ValueError("EOF")

def ping(_, name):
	global last
	try:
		if clock() >= stat[2] + 1:
			log("%r; %.3f kB/s sent, %.3f kB/s recv" % (stat, (stat[0]-last[0])/1000.0, (stat[1]-last[1])/1000.0))
			stat[2] += 1
			last = list(stat)
		for _ in range(100):
			dsock.sendto(PAYLOAD_BUFFER, PAYLOAD_SIZE, name)
			stat[0] += PAYLOAD_SIZE
		reactor.deferIdle(ping, None, name)
	except HandshakeInProgress:
		log("handshake in progress")
		reactor.scheduleMonotonic(clock() + INTERVAL, ping, name)
	except NotConnected:
		log("not connected - connecting")
		dsock.connect(name)
		reactor.scheduleMonotonic(clock() + INTERVAL, ping, name)

reactor.register(s.fileno(), select.EPOLLIN, recvmmsg, s, dsock)
reactor.deferIdle(ping, None, NAME)
reactor.run()
