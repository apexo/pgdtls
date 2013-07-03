import socket
import select
from gnutls_ffi import lib, ffi
from gnutls import PSKServerCredentials, Priority
from dtlstest import DTLSSocket
from reactor import Reactor
from util import log

class Callback(object):
	def handshake(self, conn):
		log("handshake: %r" % (conn,))

	def connected(self, conn):
		log("connected: %r" % (conn,))

	def recvfrom(self, data, data_len, seq, conn):
		#log("recvfrom: %r %r %r %r" % (data, seq, sock, peer))
		conn.sock.sendto(data, data_len, conn.name)

	def gone(self, conn):
		log("gone: %r" % (conn,))

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", 11111))

def credFunc(session, userName, datum):
	userName = ffi.string(userName)
	#log("credFunc(%r)" % ((session, userName, datum),))
	datum.data = lib.gnutls_malloc(8)
	ffi.buffer(datum.data, 8)[0:8] = b"password"
	datum.size = 8
	return 0

reactor = Reactor()

credentials = PSKServerCredentials()
credentials.setFunction(credFunc)

priority = Priority(b"SECURE192:+PSK")

def sendmsg(msg, fd=s.fileno()):
	res = lib.sendmsg(fd, msg, 0)
	#print("SENDMSG(%d, %r, 0) = %d" % (fd, msg, res))
	return res

def recvmsg(events, s, dsock, fd=s.fileno()):
	n = lib.recvmsg(fd, dsock.msg, 0)
	if n < 0:
		raise IOError(n)
	if not n:
		raise ValueError("EOF")
	#print("RECVMSG: %r: %r" % (dsock.msg, n))
	dsock.recvmsg(n)

dsock = DTLSSocket(socket.AF_INET6, Callback(), sendmsg, reactor, priority, None, credentials)

reactor.register(s.fileno(), select.EPOLLIN, recvmsg, s, dsock)
reactor.run()

#while True:
#	n, peer = s.recvfrom_into(dsock.buffer, dsock.buffer_size)
#	dsock.recvfrom(n, peer)
