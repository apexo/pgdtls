import socket
from gnutls_ffi import ffi, lib

def addrtuple_to_sockaddr(family, addr):
	if family not in (socket.AF_INET, socket.AF_INET6):
		raise ValueError("unsupported address family: %r" % (family,))
	binaddr = socket.inet_pton(family, addr[0])
	if family == socket.AF_INET:
		if len(addr) != 2:
			raise ValueError("unsupported IN address: %r" % (addr,))
		name = ffi.new("struct sockaddr_in*")
		#name.sin_family = socket.htons(family)
		name.sin_family = family
		name.sin_port = socket.htons(addr[1])
		ffi.buffer(ffi.addressof(name.sin_addr))[:] = binaddr
	else:
		if not 2 <= len(addr) <= 4:
			raise ValueError("unsupported IN6 address: %r" % (addr,))
		name = ffi.new("struct sockaddr_in6*")
		#name.sin6_family = socket.htons(family)
		name.sin6_family = family
		name.sin6_port = socket.htons(addr[1])
		name.sin6_flowinfo = 0 if len(addr) < 3 else socket.htonl(addr[2])
		ffi.buffer(ffi.addressof(name.sin6_addr))[:] = binaddr
		name.sin6_scope_id = 0 if len(addr) < 4 else socket.htonl(addr[3])
	return name

def addrtuple_to_name(family, addr):
	sockaddr = addrtuple_to_sockaddr(family, addr)
	return ffi.buffer(sockaddr)[:]

def name_to_addrtuple(name):
	assert isinstance(name, bytes)
	assert len(name) in (16, 28)
	temp = ffi.new("unsigned char[]", name)
	sa = ffi.cast("struct sockaddr*", temp)
	return sockaddr_to_addrtuple(sa)

def sockaddr_to_addrtuple(sa):
	#family = socket.ntohs(sa.sa_family)
	family = sa.sa_family
	if family == socket.AF_INET:
		sin = ffi.cast("struct sockaddr_in*", sa)
		return socket.inet_ntop(family, ffi.buffer(ffi.addressof(sin.sin_addr))[:]), socket.ntohs(sin.sin_port)
	elif family == socket.AF_INET6:
		sin6 = ffi.cast("struct sockaddr_in6*", sa)
		return socket.inet_ntop(family, ffi.buffer(ffi.addressof(sin6.sin6_addr))[:]), socket.ntohs(sin6.sin6_port), socket.ntohl(sin6.sin6_flowinfo), socket.ntohl(sin6.sin6_scope_id)
	else:
		raise ValueError("unsupported address family: %r" % (family,))

class TargetedMessage(object):
	__slots__ = ["name", "msg", "_name", "_iov"]

	def __init__(self, name):
		assert isinstance(name, bytes) and len(name) in (16, 28), (repr(name), len(name))
		self._name = ffi.new("unsigned char[]", name)
		self._iov = ffi.new("struct iovec[]", 1)
		self.name = ffi.buffer(self._name)[:]
		self.msg = ffi.new("struct msghdr*")
		self.msg.msg_name = self._name
		self.msg.msg_namelen = len(name)
		self.msg.msg_control = ffi.cast("void*", 0)
		self.msg.msg_controllen = 0
		self.msg.msg_flags = 0

	def send(self, fd):
		return lib.sendmsg(fd, self.msg, 0)

	def set_vec(self, iov, iovlen):
		self.msg.msg_iov = iov
		self.msg.msg_iovlen = iovlen

	def set(self, base, len):
		self.msg.msg_iov = self._iov
		self.msg.msg_iovlen = 1
		self._iov[0].iov_base = base
		self._iov[0].iov_len = len

class MMsgHdr(object):
	def __init__(self, vlen=16, buffer_size=2048):
		self.buffer_size = buffer_size
		self.vlen = vlen

		self.msgvec = ffi.new("struct mmsghdr[]", vlen)
		self.iov = ffi.new("struct iovec[]", vlen)
		self.name = ffi.new("struct sockaddr_storage[]", vlen)
		self.namelen = ffi.sizeof("struct sockaddr_storage")
		self.iov_data = ffi.new("unsigned char[]", buffer_size * vlen)
		self.timeout = ffi.cast("void*", 0)

		for i in range(vlen):
			hdr = self.msgvec[i].msg_hdr
			hdr.msg_name = self.name + i
			hdr.msg_namelen = self.namelen
			hdr.msg_iov = self.iov + i
			hdr.msg_iovlen = 1
			hdr.msg_control = ffi.cast("void*", 0)
			hdr.msg_controllen = 0
			hdr.msg_flags = 0

			self.iov[i].iov_base = self.iov_data + buffer_size * i
			self.iov[i].iov_len = buffer_size

	def reinit(self, n):
		for i in range(n):
			self.msgvec[i].msg_hdr.msg_namelen = self.namelen

	def recv(self, fd):
		return lib.recvmmsg(fd, self.msgvec, self.vlen, 0, self.timeout)
