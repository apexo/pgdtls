__init__.py: gnutls.h dtls.h errno.h socket.py
	python -c "import cffi;import socket;f=open('__init__.py', 'wb');f.write('CDEF = ' + repr(open('errno.h').read() + open('gnutls.h').read() + open('dtls.h').read() + socket.get_cdef(cffi.FFI())));f.close()"
	cd .. && python gnutls.py
