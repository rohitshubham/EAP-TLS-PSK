
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

struct tls_data {
	SSL_CTX *ssl;
	unsigned int tls_session_lifetime;
	int check_crl;
	int check_crl_strict;
	char *ca_cert;
	unsigned int crl_reload_interval;
	struct os_reltime crl_last_reload;
	char *check_cert_subject;
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

#endif /*endif EAP_TLS_PSK_COMMON */