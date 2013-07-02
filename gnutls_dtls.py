import os
import struct
import socket

from gnutls_ffi import lib, ffi
from gnutls_common import Datum, GNUTLSError

class ClientData(object):
	__slots__ = ["data", "size"]

	FAMILY_MAP = {
		socket.AF_INET: struct.Struct("!H4sH").pack,
		socket.AF_INET6: struct.Struct("!H16sH").pack,
	}

	def __init__(self, family, addr):
		assert family in self.FAMILY_MAP
		assert isinstance(addr, bytes)
		data = self.FAMILY_MAP[family](family, addr[0], addr[1])
		self.data = ffi.new("unsigned char[]", len(data))
		self.size = len(size)
		ffi.buffer(self.data)[:] = data

class CookieFactory(object):
	rnd = Datum(os.urandom(16))
	buffer_size = 4096

	CLIENTDATA_STRUCT = {
		socket.AF_INET: struct.Struct("!H4sH"),
		socket.AF_INET6: struct.Struct("!H16sH"),
	}
	CLIENTDATA_SIZE = max(v.size for v in CLIENTDATA_STRUCT.values())

	def __init__(self, sendto):
		self.transport = ffi.cast("void*", -1)
		self.prestate = ffi.new("gnutls_dtls_prestate_st*")
		self._client_data = ffi.new("unsigned char[]", self.CLIENTDATA_SIZE)
		self.client_data = ffi.buffer(self._client_data)
		self._buffer = ffi.new("unsigned char[]", self.buffer_size)
		self.buffer = ffi.buffer(self._buffer)
		self._push = ffi.callback("gnutls_push_func", self.push)
		self._sendto = sendto

	def push(self, transport, data, size):
		buf = ffi.buffer(data, size)
		return self._sendto(buf, self._addr)

	def verify(self, bytes, family, addr):
		self._addr = addr
		s = self.CLIENTDATA_STRUCT[family]
		bytes_addr = socket.inet_pton(family, addr[0])
		s.pack_into(self.client_data, 0, family, bytes_addr, addr[1])
		self._client_data_size = s.size
		#print("VERIFY: %r %r %r" % (self._buffer, bytearray(self._buffer)[:bytes], bytes))
		GNUTLSError.check(lib.gnutls_dtls_cookie_verify(self.rnd.v, self._client_data, s.size, self._buffer, bytes, self.prestate))

	def send(self):
		return GNUTLSError.check(lib.gnutls_dtls_cookie_send(self.rnd.v, self._client_data, self._client_data_size, self.prestate, self.transport, self._push))
