import socket
import select
from gnutls_ffi import ffi
from gnutls import PSKClientCredentials, Priority
from dtlstest import DTLSSocket, NotConnected, HandshakeInProgress
from reactor import Reactor, clock
from util import log

INTERVAL = 1
PEER = ("::1", 11111)
PAYLOAD = b"hi"*580
PAYLOAD_BUFFER = ffi.new("unsigned char[]", PAYLOAD)
PAYLOAD_SIZE = len(PAYLOAD)

stat = [0, 0, clock()]
last = list(stat)

class Callback(object):
	def connected(self, sock, peer):
		log("connected: %r %r" % (sock, peer))

	def newpeer(self, sock, peer):
		log("newpeer: %r %r" % (sock, peer))

	def recvfrom(self, data, size, seq, sock, peer):
		stat[1] += size
		#log("recvfrom: %r %r %r %r" % (data, seq, sock, peer))

	def gone(self, sock, peer):
		log("gone: %r %r" % (sock, peer))

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", 0))

reactor = Reactor()

credentials = PSKClientCredentials()
credentials.set(b"user", b"password")

priority = Priority(b"SECURE192:+PSK")

dsock = DTLSSocket(Callback(), s.sendto, reactor, priority, credentials, None)

def recvfrom(events, s, dsock):
	n, peer = s.recvfrom_into(dsock.buffer, dsock.buffer_size)
	dsock.recvfrom(n, peer)

def ping(_, addr):
	global last
	try:
		if clock() >= stat[2] + 1:
			log("%r; %.3f kB/s sent, %.3f kB/s recv" % (stat, (stat[0]-last[0])/1000.0, (stat[1]-last[1])/1000.0))
			stat[2] += 1
			last = list(stat)
		for _ in range(100):
			dsock.sendto(PAYLOAD_BUFFER, PAYLOAD_SIZE, addr)
			stat[0] += PAYLOAD_SIZE
		reactor.deferIdle(ping, None, addr)
	except HandshakeInProgress:
		log("handshake in progress")
		reactor.scheduleMonotonic(clock() + INTERVAL, ping, addr)
	except NotConnected:
		log("not connected - connecting")
		dsock.connect(addr)
		reactor.scheduleMonotonic(clock() + INTERVAL, ping, addr)

reactor.register(s.fileno(), select.EPOLLIN, recvfrom, s, dsock)
reactor.deferIdle(ping, None, PEER)

from libp.threading.Profiler import sampling_profiler, thread_init
import sys

thread_init()
sys.setcheckinterval(1)
sampling_profiler(reactor.run, 0.001)

#reactor.run()

#while True:
#	n, peer = s.recvfrom_into(dsock.buffer, dsock.buffer_size)
#	dsock.recvfrom(n, peer)
