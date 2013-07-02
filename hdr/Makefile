__init__.py: gnutls.h dtls.h
	python -c "f=open('__init__.py', 'wb');f.write('CDEF = ' + repr(open('gnutls.h').read() + open('dtls.h').read()));f.close()"
	cd .. && python gnutls.py
