import time
import socket
import struct

from gnutls_ffi import ffi
from gnutls_const import GNUTLS_SERVER, GNUTLS_CLIENT, GNUTLS_DATAGRAM, GNUTLS_NONBLOCK, GNUTLS_E_AGAIN, GNUTLS_E_BAD_COOKIE, GNUTLS_E_TIMEDOUT, GNUTLS_E_FATAL_ALERT_RECEIVED, GNUTLS_E_REHANDSHAKE, GNUTLS_E_UNEXPECTED_PACKET_LENGTH
from gnutls_common import GNUTLSError
from gnutls import Session, AnonClientCredentials
from gnutls_dtls import CookieFactory

from reactor import clock
from util import log

class TooManyConnections(Exception):
	pass

class NotConnected(Exception):
	pass

class HandshakeInProgress(NotConnected):
	pass

class Callback(object):
	def connected(self, sock, peer):
		pass

	def newpeer(self, sock, peer):
		pass

	def recvfrom(self, data, seq, sock, peer):
		pass

	def gone(self, sock, peer):
		pass

class _s_initial(object):
	@classmethod
	def enter(s, conn):
		conn.sock._callback.newpeer(conn.sock, conn.peeraddr)
		return s

	@classmethod
	def send(s, conn, data, size):
		raise NotConnected()

	@classmethod
	def recv(s, conn, data):
		raise NotConnected()

	@classmethod
	def timeout(s, conn):
		raise NotConnected()

	@classmethod
	def handshake(s, conn):
		return _s_handshake.enter(conn)

class _s_disconnected(_s_initial):
	@classmethod
	def enter(s, conn):
		conn.timeout.stop()
		conn.sock._callback.gone(conn.sock, conn.peeraddr)
		conn.sock._drop(conn.peeraddr)
		return s

	@classmethod
	def handshake(s, conn):
		raise NotConnected()

def handle_alert(conn):
	global alert
	log("ALERT on %r" % (conn,))
	alert = conn.session.alert
	log("ALERT: %r" % (alert,))

	if alert[0] == 80: # Internal Error -> hard disco
		return _s_disconnected.enter(conn)

	raise KeyboardInterrupt()

class _s_handshake(object):
	@classmethod
	def enter(s, conn):
		conn._handshake_timeout = clock() + conn.sock.handshake_timeout
		return s.recv(conn, None)

	@classmethod
	def recv(s, conn, data):
		try:
			conn.session.handshake_resume(data)
			return _s_connected.enter(conn)
		except GNUTLSError as e:
			if e.errno == GNUTLS_E_AGAIN:
				to = conn.session.dtls_timeout
				if not to:
					conn.timeout.start(conn._handshake_timeout - clock())
				else:
					conn.timeout.start(min(to * 0.001, conn._handshake_timeout - clock()))
			elif e.errno == GNUTLS_E_TIMEDOUT:
				log("TIMEDOUT, dtls timeout=%r, next timeout=%r" % (conn.session.dtls_timeout, conn.session.next_timeout))
				return _s_disconnected.enter(conn)
			elif e.errno == GNUTLS_E_FATAL_ALERT_RECEIVED:
				return handle_alert(conn)
			else:
				raise
			return s

	@classmethod
	def send(s, conn, data, size):
		raise HandshakeInProgress()

	@classmethod
	def timeout(s, conn):
		if clock() > conn._handshake_timeout:
			return _s_disconnected.enter(conn)
		return s.recv(conn, None)


class _s_connected(object):
	@classmethod
	def enter(s, conn):
		conn.sock._callback.connected(conn.sock, conn.peeraddr)
		conn.timeout.start(conn.sock.connection_timeout * 0.34)
		return s

	@classmethod
	def recv(s, conn, data):
		sock = conn.sock
		try:
			n = conn.session.recv_into_seq(data, sock._recvbuffer, sock.recvbuffer_size, sock._seq)
		except GNUTLSError as e:
			if e.errno == GNUTLS_E_AGAIN:
				# apparently this happens when the server restarts while the client thinks it has an active session
				return _s_disconnected.enter(conn)
			elif e.errno == GNUTLS_E_REHANDSHAKE:
				return _s_handshake.enter(conn)
			else:
				raise
		sock._callback.recvfrom(sock._recvbuffer, n, sock._get_seq(), sock, conn)
		return s

	@classmethod
	def send(s, conn, data, size):
		return s, conn.session.send(data, size)

	@classmethod
	def timeout(s, conn):
		dt = clock() - min(conn.last_inbound, conn.last_outbound)
		if dt > conn.sock.connection_timeout:
			return _s_disconnected.enter(conn)
		conn.timeout.start(conn.sock.connection_timeout * 0.34)
		return s

	@classmethod
	def handshake(s, conn):
		return _s_handshake.enter(conn)

class Timeout(object):
	__slots__ = ["_id", "_timeout", "_conn", "_pending", "_stopped"]

	def __init__(self, conn):
		self._id = 0
		self._timeout = 0
		self._pending = False
		self._stopped = False
		self._conn = conn

	def start(self, timeout):
		self._id += 1
		self._timeout = clock() + timeout
		if not self._pending:
			self._conn.reactor.scheduleMonotonic(self._timeout, self, self._id)
			self._pending = True
		self._stopped = False

	def stop(self):
		if self._pending:
			self._stopped = True

	def __call__(self, t, id_):
		if self._stopped:
			self._pending = self._stopped = False
			return
		if id_ == self._id:
			self._pending = False
			self._conn.state = self._conn.state.timeout(self._conn)
			return
		self._conn.reactor.scheduleMonotonic(self._timeout, self, self._id)

class DTLSConnection(object):
	__slots__ = ["peeraddr", "client", "session", "state", "reactor", "timeout", "sock", "_handshake_timeout", "last_outbound", "last_inbound"]

	def __init__(self, sock, priority, credentials, peeraddr, client, prestate=None):
		assert client == (prestate is None)
		assert priority is not None
		assert credentials is not None
		self.peeraddr = peeraddr
		self.client = client
		flags = (GNUTLS_CLIENT if client else GNUTLS_SERVER) | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK
		self.session = Session(flags, sock._sendto, peeraddr)
		self.session.priority = priority
		self.session.credentials = AnonClientCredentials()
		self.reactor = sock._reactor
		self.sock = sock
		self.timeout = Timeout(self)
		self.session.credentials = credentials
		if not client:
			self.session.dtls_prestate = prestate
		self.last_inbound = self.last_outbound = clock()
		self.state = _s_initial.enter(self)

	def connect(self):
		self.state = self.state.handshake(self)

	def recv(self, data):
		self.state = self.state.recv(self, data)

	def send(self, data, size):
		self.state, n = self.state.send(self, data, size)
		return n

	def __repr__(self):
		return "<DTLSConnection with peer %s in state %s>" % (self.peeraddr, self.state)


class DTLSSocket(object):
	connection_timeout = 60
	connection_limit = 100
	handshake_timeout = 32
	recvbuffer_size = 65536
	unpack_seq = struct.Struct("!Q").unpack_from

	def __init__(self, callback, sendto, reactor, priority, clientCredentials=None, serverCredentials=None):
		self._connections = {}
		self._callback = callback
		self._sendto = sendto
		self._reactor = reactor
		self._cookieFactory = CookieFactory(sendto)
		self._priority = priority
		self._clientCredentials = clientCredentials
		self._serverCredentials = serverCredentials
		self.buffer = self._cookieFactory.buffer
		self.buffer_size = self._cookieFactory.buffer_size
		self._recvbuffer = ffi.new("unsigned char[]", self.recvbuffer_size)
		self.recvbuffer = ffi.buffer(self._recvbuffer)
		self._seq = ffi.new("unsigned char[]", 8)
		self._seq2 = ffi.cast("void*", self._seq)
		self._seqb = ffi.buffer(self._seq)

	def _sendto(self, data, addr):
		log("SEND %r to %r" % (len(data), addr))
		return self.__sendto(data, addr)

	def _get_seq(self, unpack_from=struct.Struct("!Q").unpack_from):
		return unpack_from(self._seqb, 0)[0]

	def connect(self, peeraddr):
		if len(self._connections) >= self.connection_limit:
			raise TooManyConnections()
		connection = DTLSConnection(self, self._priority, self._clientCredentials, peeraddr, True)
		self._connections[peeraddr] = connection
		connection.connect()

	def _drop(self, peeraddr):
		key = peeraddr[:2]
		self._connections.pop(key, None)

	def recvfrom(self, bytes, peeraddr):
		#log("RECV %r from %r" % (bytes, peeraddr))
		key = peeraddr[:2]
		connection = self._connections.get(key)
		if connection is None:
			try:
				self._cookieFactory.verify(bytes, socket.AF_INET if len(peeraddr) == 2 else socket.AF_INET6, peeraddr)
			except GNUTLSError as e:
				if e.errno in (GNUTLS_E_BAD_COOKIE, GNUTLS_E_UNEXPECTED_PACKET_LENGTH):
					self._cookieFactory.send()
				else:
					raise
				return
			if len(self._connections) >= self.connection_limit:
				return
			connection = DTLSConnection(self, self._priority, self._serverCredentials, peeraddr, False, self._cookieFactory.prestate)
			self._connections[key] = connection
			connection.session._queue.append(ffi.buffer(self._cookieFactory._buffer, bytes))
			connection.connect()
		else:
			connection.last_inbound = clock()
			connection.recv(ffi.buffer(self._cookieFactory._buffer, bytes))

	def sendto(self, data, size, peeraddr):
		key = peeraddr[:2]
		connection = self._connections.get(key)
		if connection is None:
			raise NotConnected()
		connection.last_outbound = clock()
		return connection.send(data, size)
