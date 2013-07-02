import socket
import select
from gnutls_ffi import lib, ffi
from gnutls import PSKServerCredentials, Priority
from dtlstest import DTLSSocket
from reactor import Reactor
from util import log

class Callback(object):
	def newpeer(self, sock, addr):
		log("newpeer: %r %r" % (sock, addr))

	def connected(self, sock, peer):
		log("connected: %r %r" % (sock, peer))

	def recvfrom(self, data, size, seq, sock, peer):
		#log("recvfrom: %r %r %r %r" % (data, seq, sock, peer))
		sock.sendto(data, size, peer.peeraddr)

	def gone(self, sock, peer):
		log("gone: %r %r" % (sock, peer))

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

dsock = DTLSSocket(Callback(), s.sendto, reactor, priority, None, credentials)

def recvfrom(events, s, dsock):
	n, peer = s.recvfrom_into(dsock.buffer, dsock.buffer_size)
	dsock.recvfrom(n, peer)

reactor.register(s.fileno(), select.EPOLLIN, recvfrom, s, dsock)
reactor.run()

#while True:
#	n, peer = s.recvfrom_into(dsock.buffer, dsock.buffer_size)
#	dsock.recvfrom(n, peer)
