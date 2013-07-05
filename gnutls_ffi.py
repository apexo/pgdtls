import cffi

__all__ = ["ffi", "lib"]

from gnutls_const import *
import hdr

ffi = cffi.FFI()
ffi.cdef(hdr.CDEF + """
int _io_TUNSETIFF(void);
int _io_SIOCSIFMTU(void);
""")

lib = ffi.verify("""
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#define __USE_GNU 1
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>

#include <linux/ioctl.h>
#include <sys/ioctl.h>

int _io_TUNSETIFF(void) {
	return TUNSETIFF;
}
int _io_SIOCSIFMTU(void) {
	return SIOCSIFMTU;
}
""", libraries=["gnutls"])
