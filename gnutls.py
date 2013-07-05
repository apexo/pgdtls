import errno

from gnutls_ffi import ffi, lib
from gnutls_const import *
from gnutls_dtls import *
from gnutls_common import GNUTLSError, GNUTLSCertificateError, cstring_wrap, Datum, _GC

class _AnonCredentials(object):
	_type = lib.GNUTLS_CRD_ANON

class AnonServerCredentials(_AnonCredentials, _GC):
	__slots__ = ["v", "ptr"]

	_gc = lib.gnutls_anon_free_server_credentials
	_alloc = lib.gnutls_anon_allocate_server_credentials
	_typename = "gnutls_anon_server_credentials_t"

class AnonClientCredentials(_AnonCredentials, _GC):
	__slots__ = ["v", "ptr"]

	_gc = lib.gnutls_anon_free_client_credentials
	_alloc = lib.gnutls_anon_allocate_client_credentials
	_typename = "gnutls_anon_client_credentials_t"

class _PSKCredentials(object):
	_type = lib.GNUTLS_CRD_PSK

class PSKServerCredentials(_PSKCredentials, _GC):
	__slots__ = ["v", "ptr", "_function", "_paramsFunction"]

	_gc = lib.gnutls_psk_free_server_credentials
	_alloc = lib.gnutls_psk_allocate_server_credentials
	_typename = "gnutls_psk_server_credentials_t"

	def setFile(self, password_file):
		GNUTLSError.check(lib.gnutls_psk_set_server_credentials_file(self.v, cstring_wrap(password_file)))

	def setFunction(self, func):
		self._function = ffi.callback("gnutls_psk_server_credentials_function", func)
		lib.gnutls_psk_set_server_credentials_function(self.v, self._function)

	def setHint(self, hint):
		GNUTLSError.check(lib.gnutls_psk_set_server_credentials_hint(self.v, cstring_wrap(hint)))

	def setDHParams(self, dh_params):
		lib.gnutls_psk_set_server_dh_params(self.v, dh_params.v[0])

	def setParamsFunction(self, func):
		self._paramsFunction = ffi.callback("gnutls_params_function", func)
		lib.gnutls_psk_set_server_params_function(self.v, self._paramsFunction)

class PSKClientCredentials(_PSKCredentials, _GC):
	__slots__ = ["v", "ptr", "_function"]

	_gc = lib.gnutls_psk_free_client_credentials
	_alloc = lib.gnutls_psk_allocate_client_credentials
	_typename = "gnutls_psk_client_credentials_t"

	def set(self, username, key, flags=lib.GNUTLS_PSK_KEY_RAW):
		assert flags in (lib.GNUTLS_PSK_KEY_RAW, lib.GNUTLS_PSK_KEY_HEX)
		key = Datum(key)
		username = cstring_wrap(username)
		GNUTLSError.check(lib.gnutls_psk_set_client_credentials(self.v, username, key.v, flags))

	def setFunction(self, func):
		self._function = ffi.callback("gnutls_psk_client_credentials_function", func)
		lib.gnutls_psk_set_client_credentials_function(self.v, self._function)

class CertificateCredentials(object):
	__slots__ = ["v", "ptr", "_verifyFunction"]

	_type = lib.GNUTLS_CRD_CERTIFICATE
	_gc = lib.gnutls_certificate_free_credentials
	_alloc = lib.gnutls_certificate_allocate_credentials
	_typename = "gnutls_certificate_credentials_t"

	def setX509SystemTrust(self):
		return GNUTLSError.check(lib.gnutls_certificate_set_x509_system_trust(self.v))

	def setX509TrustFile(self, cafile, type):
		assert type in (lib.GNUTLS_X509_FMT_PEM, lib.GNUTLS_X509_FMT_DER)
		return GNUTLSError.check(lib.gnutls_certificate_set_x509_trust_file(self.v, cstring_wrap(cafile), type))

	def setX509TrustMem(self, ca, type):
		assert type in (lib.GNUTLS_X509_FMT_PEM, lib.GNUTLS_X509_FMT_DER)
		ca = Datum(ca)
		return GNUTLSError.check(lib.gnutls_certificate_set_x509_trust_mem(self.v, ca.v, type))

	def setX509CRLFile(self, crtfile, type):
		assert type in (lib.GNUTLS_X509_FMT_PEM, lib.GNUTLS_X509_FMT_DER)
		return GNUTLSError.check(lib.gnutls_certificate_set_x509_crl_file(self.v, cstring_wrap(crlfile), type))

	def setX509CRLMem(self, ca, type):
		assert type in (lib.GNUTLS_X509_FMT_PEM, lib.GNUTLS_X509_FMT_DER)
		crl = Datum(crl)
		return GNUTLSError.check(lib.gnutls_certificate_set_x509_crl_mem(self.v, crl.v, type))

	def setX509KeyFile(self, certfile, keyfile, type):
		assert type in (lib.GNUTLS_X509_FMT_PEM, lib.GNUTLS_X509_FMT_DER)
		return GNUTLSError.check(lib.gnutls_certificate_set_x509_key_file(self.v, cstring_wrap(certfile), cstring_wrap(keyfile), type))

	def setX509KeyMem(self, cert, key, type):
		assert type in (lib.GNUTLS_X509_FMT_PEM, lib.GNUTLS_X509_FMT_DER)
		cert = Datum(cert)
		key = Datum(key)
		return GNUTLSError.check(lib.gnutls_certificate_set_x509_key_mem(self.v, cert.v, key.v, type))

	def setX509Key(self, cert_list, key):
		# TODO
		pass

	def setX509Trust(self, cert_list, key):
		# TODO
		pass

	def setX509CRL(self, cert_list, key):
		# TODO
		pass

	def sendX509RDNSequence(self, status):
		assert status in (0, 1)
		lib.gnutls_certificate_send_x509_rdn_sequence(self.v, status)

	@property
	def verifyFlags(self):
		return self._verifyFlags

	@verifyFlags.setter
	def verifyFlags(self, flags):
		self._verifyFlags = flags
		lib.gnutls_certificate_set_verify_flags(self.v, flags)

	@property
	def verifyFunction(self):
		return self._verifyFunction

	@verifyFunction.setter
	def verifyFunction(self, func):
		self._verifyFunction = ffi.callback("gnutls_certificate_verify_function", func)
		lib.gnutls_certificate_set_verify_function(self._verifyFunction)

class Session(object):
	__slots__ = ["v", "ptr", "_credentials", "_sendmsg", "_addr", "__push", "__pull_timeout", "__pull", "_queue", "next_timeout", "__vec_push", "_msg"]

	handshake_timeout = 5000

	def __init__(self, flags, sendmsg, msg):
		self.ptr = ffi.new("gnutls_session_t*")
		GNUTLSError.check(lib.gnutls_init(self.ptr, flags))
		self.v = self.ptr[0]
		self._msg = msg
		self._sendmsg = sendmsg
		self.__push = ffi.callback("gnutls_push_func", self._push)
		self.__vec_push = ffi.callback("gnutls_vec_push_func", self._vec_push)
		self.__pull = ffi.callback("gnutls_pull_func", self._pull)
		self.__pull_timeout = ffi.callback("gnutls_pull_timeout_func", self._pull_timeout)
		lib.gnutls_transport_set_push_function(self.v, self.__push)
		lib.gnutls_transport_set_vec_push_function(self.v, self.__vec_push)
		lib.gnutls_transport_set_pull_function(self.v, self.__pull)
		lib.gnutls_transport_set_pull_timeout_function(self.v, self.__pull_timeout)
		#lib.gnutls_handshake_set_timeout(self.v, self.handshake_timeout)
		self._queue = None

	@property
	def credentials(self):
		return self._credentials

	@credentials.setter
	def credentials(self, credentials):
		if credentials is None:
			lib.gnutls.credentials_clear(self.v)
		else:
			GNUTLSError.check(lib.gnutls_credentials_set(self.v, credentials._type, credentials.v))
		self._credentials = credentials

	def certificateVerifyPeers(self, hostname):
		hostname = None if hostname is None else cstring_wrap(hostname)
		status = ffi.new("unsigned int*")
		GNUTLSError.check(lib.gnutls_certificate_verify_peers3(self.v, hostname, status))
		GNUTLSCertificateError.check(status[0])

	def handshake(self, data):
		self._queue = data # data may be None
		GNUTLSError.check(lib.gnutls_handshake(self.v))

	def recv_into_seq(self, data, buffer, size, seq):
		self._queue = data # data may not be None
		return GNUTLSError.check(lib.gnutls_record_recv_seq(self.v, buffer, size, seq))

	def send(self, data, size):
		return GNUTLSError.check(lib.gnutls_record_send(self.v, data, size))

	def _push(self, transport, data, length):
		self._msg.set(data, length)
		return self._sendmsg(self._msg.msg)

	def _vec_push(self, transport, iov, iovcnt, tt=ffi.typeof("struct iovec*")):
		self._msg.set_vec(ffi.cast(tt, iov), iovcnt)
		return self._sendmsg(self._msg.msg)

	def _pull(self, transport, buffer, size):
		data = self._queue
		self._queue = None
		if not data:
			lib.gnutls_transport_set_errno(self.v, errno.EAGAIN)
			return -1
		target = ffi.buffer(buffer, size)
		n = min(size, len(data))
		target[:n] = data[:n]
		return n

	def _pull_timeout(self, transport, timeout):
		if self._queue:
			return 1
		self.next_timeout = timeout
		return 0

	dtls_prestate = property(None, lambda self, prestate: lib.gnutls_dtls_prestate_set(self.v, prestate))
	priority = property(None, lambda self, priority: lib.gnutls_priority_set(self.v, priority.v))

	@property
	def alert(self):
		alert = lib.gnutls_alert_get(self.v)
		return alert, ffi.string(lib.gnutls_alert_get_name(alert))

	@property
	def dtls_timeout(self):
		return lib.gnutls_dtls_get_timeout(self.v)

	@property
	def dtls_data_mtu(self):
		return lib.gnutls_dtls_get_data_mtu(self.v)

	def __del__(self, gc=lib.gnutls_deinit):
		gc(self.ptr)

class Priority(object):
	__slots__ = ["v", "ptr"]

	def __init__(self, priorities):
		global b, res, err_pos
		self.ptr = ffi.new("gnutls_priority_t*")
		b = cstring_wrap(priorities)
		err_pos = ffi.new("const char**")
		res = lib.gnutls_priority_init(self.ptr, b, err_pos)
		err_pos = int(ffi.cast("intptr_t", err_pos[0])) - int(ffi.cast("intptr_t", b))
		GNUTLSError.check(res, priorities, err_pos)
		self.v = self.ptr[0]

def global_init():
	GNUTLSError.check(lib.gnutls_global_init())

global_init()
"""
s = Session(GNUTLS_SERVER | GNUTLS_DATAGRAM)
creds = PSKClientCredentials()
creds.set(b"hi", b"there", lib.GNUTLS_PSK_KEY_RAW)
creds = PSKServerCredentials()
creds.setFunction(lambda u: b"okay")
#sc = CertificateCredentials()
#s.credentials = sc
#log(sc.setX509TrustFile(b"/usr/share/ca-certificates/mozilla/Visa_eCommerce_Root.crt", lib.GNUTLS_X509_FMT_PEM))
"""
