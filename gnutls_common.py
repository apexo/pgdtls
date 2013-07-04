from gnutls_ffi import ffi
from gnutls_const import GNUTLS_E_MAP

class _GNUTLSError(Exception):
	def __init__(self, errno, *args):
		super(_GNUTLSError, self).__init__(errno, *args)
		self.errno = errno

	@classmethod
	def check(cls, res, *args):
		if res is None:
			raise Exception("void")
		if res < 0:
			raise cls(res, *args)
		return res

class GNUTLSError(_GNUTLSError):
	def __init__(self, errno, *args):
		name = GNUTLS_E_MAP.get(errno, "???")
		super(GNUTLSError, self).__init__(errno, name, *args)
		self.name = name

class GNUTLSCertificateError(_GNUTLSError):
	pass

def cstring_wrap(data):
	assert isinstance(data, bytes)
	return ffi.new("unsigned char[]", data)

def bytes_wrap(data):
	assert isinstance(data, bytes)
	result = ffi.new("unsigned char[]", len(data))
	ffi.buffer(result)[:] = data
	return result

class Datum(object):
	__slots__ = ["_data", "v"]

	def __init__(self, data):
		self._data = bytes_wrap(data)
		self.v = ffi.new("gnutls_datum_t*")
		self.v.data = self._data
		self.v.size = len(data)

class _GC(object):
	def __init__(self):
		self.ptr = ffi.new(self._typename + "*")
		GNUTLSError.check(self._alloc(self.ptr))
		self.v = self.ptr[0]
		super(_GC, self).__init__()

	def __del__(self):
		self._gc(self.v)
