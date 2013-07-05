import os
import struct

from .ffi import lib, ffi
from .const import GNUTLS_SERVER, GNUTLS_CLIENT, GNUTLS_DATAGRAM, GNUTLS_NONBLOCK, GNUTLS_E_AGAIN, GNUTLS_E_BAD_COOKIE, GNUTLS_E_TIMEDOUT, GNUTLS_E_FATAL_ALERT_RECEIVED, GNUTLS_E_REHANDSHAKE, GNUTLS_E_UNEXPECTED_PACKET_LENGTH
from .common import GNUTLSError, Datum
from . import Session
from .reactor import clock
from .util import log
from .sockutil import TargetedMessage, name_to_addrtuple

class CookieFactory(object):
	rnd = Datum(os.urandom(16))

	def __init__(self, sendmsg):
		self.transport = ffi.cast("void*", -1)
		self.prestate = ffi.new("gnutls_dtls_prestate_st*")
		self._push = ffi.callback("gnutls_push_func", self.push)
		self._sendmsg = sendmsg

		self._iov = ffi.new("struct iovec[]", 1)

		self._msg = ffi.new("struct msghdr*")
		self._msg.msg_control = ffi.cast("void*", 0)
		self._msg.msg_controllen = 0
		self._msg.msg_flags = 0
		self._msg.msg_iov = self._iov
		self._msg.msg_iovlen = 1

	def push(self, transport, data, size):
		m = self._msg
		m.msg_iov[0].iov_base = data
		m.msg_iov[0].iov_len = size
		return self._sendmsg(m)

	def verify(self, data, bytes, name, namelen):
		GNUTLSError.check(lib.gnutls_dtls_cookie_verify(self.rnd.v, name, namelen, data, bytes, self.prestate))

	def send(self, name, namelen):
		self._msg.msg_name = name
		self._msg.msg_namelen = namelen
		return GNUTLSError.check(lib.gnutls_dtls_cookie_send(self.rnd.v, name, namelen, self.prestate, self.transport, self._push))

class TooManyConnections(Exception):
	pass

class NotConnected(Exception):
	pass

class HandshakeInProgress(NotConnected):
	pass

class Callback(object):
	def handshake(self, conn):
		pass

	def connected(self, conn):
		pass

	def recvfrom(self, data, data_len, seq, conn):
		pass

	def gone(self, conn):
		pass

class _s_initial(object):
	@classmethod
	def enter(s, conn):
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
	def handshake(s, conn, data):
		return _s_handshake.enter(conn, data)

class _s_disconnected(_s_initial):
	@classmethod
	def enter(s, conn):
		conn.timeout.stop()
		conn.sock._drop(conn.name)
		conn.state = s
		conn.sock._callback.gone(conn)

	@classmethod
	def handshake(s, conn, data):
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
	def enter(s, conn, data):
		conn._handshake_timeout = clock() + conn.sock.handshake_timeout
		conn.state = s
		conn.sock._callback.handshake(conn)
		s.recv(conn, data)

	@classmethod
	def recv(s, conn, data):
		try:
			conn.session.handshake(data)
			_s_connected.enter(conn)
		except GNUTLSError as e:
			if e.errno == GNUTLS_E_AGAIN:
				to = conn.session.dtls_timeout
				if not to:
					conn.timeout.start(conn._handshake_timeout - clock())
				else:
					conn.timeout.start(min(to * 0.001, conn._handshake_timeout - clock()))
			elif e.errno == GNUTLS_E_TIMEDOUT:
				log("TIMEDOUT, dtls timeout=%r, next timeout=%r" % (conn.session.dtls_timeout, conn.session.next_timeout))
				_s_disconnected.enter(conn)
			elif e.errno == GNUTLS_E_FATAL_ALERT_RECEIVED:
				handle_alert(conn)
			else:
				raise

	@classmethod
	def send(s, conn, data, size):
		raise HandshakeInProgress()

	@classmethod
	def timeout(s, conn):
		if clock() > conn._handshake_timeout:
			return _s_disconnected.enter(conn)
		s.recv(conn, None)


class _s_connected(object):
	@classmethod
	def enter(s, conn):
		conn.timeout.start(conn.sock.connection_timeout * 0.34)
		conn.state = s
		conn.sock._callback.connected(conn)

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
				return _s_handshake.enter(conn, None) # maybe w/ data, does not seem to make much of a difference?
			else:
				raise
		sock._callback.recvfrom(sock._recvbuffer, n, sock._get_seq(), conn)

	@classmethod
	def send(s, conn, data, size):
		return conn.session.send(data, size)

	@classmethod
	def timeout(s, conn):
		dt = clock() - min(conn.last_inbound, conn.last_outbound)
		if dt > conn.sock.connection_timeout:
			return _s_disconnected.enter(conn)
		conn.timeout.start(conn.sock.connection_timeout * 0.34)

	@classmethod
	def handshake(s, conn):
		_s_handshake.enter(conn, None)

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
			return self._conn.state.timeout(self._conn)
		self._conn.reactor.scheduleMonotonic(self._timeout, self, self._id)

class DTLSConnection(object):
	__slots__ = ["name", "client", "session", "state", "reactor", "timeout", "sock", "_handshake_timeout", "last_outbound", "last_inbound", "msg"]

	def __init__(self, sock, priority, credentials, name, client, prestate=None):
		assert client == (prestate is None)
		assert priority is not None
		assert credentials is not None
		self.client = client
		flags = (GNUTLS_CLIENT if client else GNUTLS_SERVER) | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK
		self.name = name
		self.msg = TargetedMessage(name)
		self.session = Session(flags, sock._sendmsg, self.msg)
		self.session.priority = priority
		self.reactor = sock._reactor
		self.sock = sock
		self.timeout = Timeout(self)
		self.session.credentials = credentials
		if not client:
			self.session.dtls_prestate = prestate
		self.last_inbound = self.last_outbound = clock()
		self.state = _s_initial.enter(self)

	def connect(self, data=None):
		self.state.handshake(self, data)

	def recv(self, data):
		self.last_inbound = clock()
		self.state.recv(self, data)

	def send(self, data, size):
		self.last_outbound = clock()
		return self.state.send(self, data, size)

	@property
	def peeraddr(self):
		return name_to_addrtuple(self.name)

	def __repr__(self):
		return "<DTLSConnection with peer %s in state %s>" % (self.peeraddr, self.state)


class DTLSSocket(object):
	connection_timeout = 60
	connection_limit = 100
	handshake_timeout = 32
	recvbuffer_size = 65536

	def __init__(self, callback, sendmsg, reactor, priority, clientCredentials=None, serverCredentials=None):
		self._connections = {}
		self._callback = callback
		self._sendmsg = sendmsg
		self._reactor = reactor
		self._cookieFactory = CookieFactory(sendmsg)
		self._priority = priority
		self._clientCredentials = clientCredentials
		self._serverCredentials = serverCredentials
		self._recvbuffer = ffi.new("unsigned char[]", self.recvbuffer_size)
		self.recvbuffer = ffi.buffer(self._recvbuffer)
		self._seq = ffi.new("unsigned char[]", 8)
		self._seq2 = ffi.cast("void*", self._seq)
		self._seqb = ffi.buffer(self._seq)

	def _get_seq(self, unpack_from=struct.Struct("!Q").unpack_from):
		return unpack_from(self._seqb, 0)[0]

	def connect(self, name):
		assert isinstance(name, bytes)
		name_to_addrtuple(name)

		connection = self._connections.get(name)
		if connection is not None:
			return connection
		if len(self._connections) >= self.connection_limit:
			raise TooManyConnections()
		connection = DTLSConnection(self, self._priority, self._clientCredentials, name, True)
		self._connections[name] = connection
		connection.connect()
		return connection

	def _drop(self, name):
		self._connections.pop(name, None)

	def recvmsg(self, data, datalen, name, namelen):
		bname = ffi.buffer(name, namelen)[:]

		connection = self._connections.get(bname)
		if connection is None:
			try:
				self._cookieFactory.verify(data, datalen, name, namelen)
			except GNUTLSError as e:
				if e.errno in (GNUTLS_E_BAD_COOKIE, GNUTLS_E_UNEXPECTED_PACKET_LENGTH):
					self._cookieFactory.send(name, namelen)
				else:
					raise
				return
			if len(self._connections) >= self.connection_limit:
				return
			connection = DTLSConnection(self, self._priority, self._serverCredentials, bname, False, self._cookieFactory.prestate)
			self._connections[bname] = connection
			connection.connect(ffi.buffer(data, datalen))
		else:
			connection.recv(ffi.buffer(data, datalen))

	def sendto(self, data, size, name):
		connection = self._connections.get(name)
		if connection is None:
			raise NotConnected(name_to_addrtuple(name))
		return connection.send(data, size)
