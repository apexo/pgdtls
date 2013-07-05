__init__.py: gnutls.h dtls.h errno.h socket.py if.h
	python -c "import cffi;import socket;f=open('__init__.py', 'wb');f.write('CDEF = ' + repr(open('errno.h').read() + open('gnutls.h').read() + open('dtls.h').read() + socket.get_cdef(cffi.FFI()) + open('if.h').read() + open('unistd.h').read()));f.close()"
	cd .. && python gnutls.py
	cd .. && python3 gnutls.py
	#cd .. && pypy gnutls.py		# disabled for now, seems to have problems with struct mmsghdr

clean:
	rm -f __init__.py
