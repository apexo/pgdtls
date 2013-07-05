import os
import socket

from gnutls_ffi import lib, ffi
from gnutls_common import Datum, GNUTLSError

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
		m.msg_name = self._name
		m.msg_namelen = self._namelen
		m.msg_iov[0].iov_base = data
		m.msg_iov[0].iov_len = size
		return self._sendmsg(m)

	def verify(self, data, bytes, name, namelen):
		GNUTLSError.check(lib.gnutls_dtls_cookie_verify(self.rnd.v, name, namelen, data, bytes, self.prestate))

	def send(self, name, namelen):
		return GNUTLSError.check(lib.gnutls_dtls_cookie_send(self.rnd.v, name, namelen, self.prestate, self.transport, self._push))
