import cffi

__all__ = ["ffi", "lib"]

from gnutls_const import *
import hdr

ffi = cffi.FFI()
ffi.cdef(hdr.CDEF)
lib = ffi.verify("""
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
""", libraries=["gnutls"])
