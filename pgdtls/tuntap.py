import socket
import fcntl
import os
import sys
from .ffi import ffi, lib

TUN_READQ_SIZE = 500 # Read queue size

# TUN device flags
TUN_TUN_DEV = 0x0001
TUN_TAP_DEV = 0x0002
TUN_TYPE_MASK = 0x000f

TUN_FASYNC = 0x0010
TUN_NOCHECKSUM = 0x0020
TUN_NO_PI = 0x0040

TUN_ONE_QUEUE = 0x0080 # This flag has no real effect
TUN_PERSIST = 0x0100
TUN_VNET_HDR = 0x0200
TUN_TAP_MQ = 0x0400

# TUNSETIFF ifr flags
IFF_TUN = 0x0001
IFF_TAP	= 0x0002
IFF_NO_PI = 0x1000
IFF_ONE_QUEUE = 0x2000 # This flag has no real effect
IFF_VNET_HDR = 0x4000
IFF_TUN_EXCL = 0x8000
IFF_MULTI_QUEUE = 0x0100
IFF_ATTACH_QUEUE = 0x0200
IFF_DETACH_QUEUE = 0x0400

TUN_PKT_STRIP = 0x0001

IFHWADDRLEN = 6
IFNAMSIZ = 16

TUNSETIFF = lib._io_TUNSETIFF()
SIOCSIFMTU = lib._io_SIOCSIFMTU()

class TUNTAP(object):
	def __init__(self):
		self.fd = None
		self._name = None
		self.bufsize = 2048
		self.buf = ffi.new("unsigned char[]", self.bufsize)

	@property
	def name(self):
		if self._name is None:
			return None
		if sys.version_info.major == 3:
			return self._name.decode("ascii")
		return self._name

	def init(self, tun=0):
		self.fd = os.open("/dev/net/tun", os.O_RDWR)
		ifr = ffi.new("struct ifreq*")
		ifr.ifr_ifru.ifru_flags = (IFF_TUN if tun else IFF_TAP) | IFF_NO_PI
		fcntl.ioctl(self.fd, TUNSETIFF, ffi.buffer(ifr), True)
		self._name = ffi.string(ifr.ifr_ifrn.ifrn_name)

	def setMTU(self, mtu):
		s = socket.socket(socket.AF_INET)
		ifr = ffi.new("struct ifreq*")
		n = self._name + b"\0" * (16 - len(self._name))
		ffi.buffer(ifr.ifr_ifrn.ifrn_name)[:] = n
		ifr.ifr_ifru.ifru_mtu = mtu
		fcntl.ioctl(s.fileno(), SIOCSIFMTU, ffi.buffer(ifr), True)

	def __del__(self, _close=os.close):
		if self.fd is not None:
			_close(self.fd)
			self.fd = None

	def read(self):
		res = lib.read(self.fd, self.buf, self.bufsize)
		if res < 0:
			raise IOError(getattr(lib, "__errno_location")())
		return res

	def write(self, buf, count):
		res = lib.write(self.fd, buf, count)
		if res < 0:
			raise IOError(getattr(lib, "__errno_location")())
		return res
