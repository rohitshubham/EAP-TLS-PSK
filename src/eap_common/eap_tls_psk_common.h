
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


#ifndef EAP_TLS_PSK_COMMON_H
#define EAP_TLS_PSK_COMMON_H

/* Section : definitions */
#define EAP_TLS_PSK_SHARED_KEY_LEN 16


/* Section : data structures */
struct eap_tls_psk_data {
    SSL_CTX *ctx;
    struct tls_connection *conn;
    const u8 *psk;
    u8 eap_type;
};

struct eap_tls_psk_server_data {
    SSL_CTX *ctx;
    struct wpabuf *tls_in;
    const u8 *psk;
    u8 eap_type;
	enum { START, CONTINUE, SUCCESS, FAILURE } state;
    enum { MSG, FRAG_ACK, WAIT_FRAG_ACK } ssl_state;
    struct wpabuf tmpbuf;
};

/* Section : common methods */
static int psk_use_session_cb(SSL *s, const EVP_MD *md,
                              const unsigned char **id, size_t *idlen,
                              SSL_SESSION **sess);


static const char * openssl_content_type(int content_type);

static const char * openssl_handshake_type(int content_type, const u8 *buf,
					   size_t len);

static void tls_msg_cb(int write_p, int version, int content_type,
		       const void *buf, size_t len, SSL *ssl, void *arg);

static void set_psk(const u8 *data);

static  const char * eap_tls_state_txt(int state);

static void eap_tls_state(struct eap_tls_psk_server_data *data, int state);

static int eap_server_tls_process_cont(struct eap_tls_psk_server_data *data,
				       const u8 *buf, size_t len);

static void eap_server_tls_psk_free_in_buf(struct eap_tls_psk_server_data *data);
#endif /*endif EAP_TLS_PSK_COMMON */