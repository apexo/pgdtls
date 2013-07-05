void gnutls_dtls_set_timeouts (gnutls_session_t session,
			       unsigned int retrans_timeout,
			       unsigned int total_timeout);

unsigned int gnutls_dtls_get_mtu (gnutls_session_t session);
unsigned int gnutls_dtls_get_data_mtu (gnutls_session_t session);

void gnutls_dtls_set_mtu (gnutls_session_t session, unsigned int mtu);
int gnutls_dtls_set_data_mtu (gnutls_session_t session, unsigned int mtu);

unsigned int gnutls_dtls_get_timeout (gnutls_session_t session);

/**
 * gnutls_dtls_prestate_st:
 * @record_seq: record sequence number
 * @hsk_read_seq: handshake read sequence number
 * @hsk_write_seq: handshake write sequence number
 *
 * DTLS cookie prestate struct.  This is usually never modified by
 * the application, it is used to carry the cookie data between
 * gnutls_dtls_cookie_send(), gnutls_dtls_cookie_verify() and
 * gnutls_dtls_prestate_set().
 */
  typedef struct
  {
    unsigned int record_seq;
    unsigned int hsk_read_seq;
    unsigned int hsk_write_seq;
  } gnutls_dtls_prestate_st;

  int gnutls_dtls_cookie_send (gnutls_datum_t* key,
			       void* client_data, size_t client_data_size,
			       gnutls_dtls_prestate_st* prestate,
			       gnutls_transport_ptr_t ptr,
			       gnutls_push_func push_func);

  int gnutls_dtls_cookie_verify (gnutls_datum_t* key,
				 void* client_data, size_t client_data_size,
				 void* _msg, size_t msg_size,
				 gnutls_dtls_prestate_st* prestate);

  void gnutls_dtls_prestate_set (gnutls_session_t session,
				 gnutls_dtls_prestate_st* prestate);

  unsigned int gnutls_record_get_discarded (gnutls_session_t session);
