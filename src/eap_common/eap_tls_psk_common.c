#include "includes.h"

#include <stdio.h>
#include "common.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

//SSL specific code
static SSL_SESSION *psksess = NULL;
const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
const unsigned char tls13_aes256gcmsha384_id[] = { 0x13, 0x02 };
static char *psk_identity = "Client_identity";

const char *psk_key;



// TLS PSK Session callback . Builds a new Session Object 
static int psk_use_session_cb(SSL *s, const EVP_MD *md,
                              const unsigned char **id, size_t *idlen,
                              SSL_SESSION **sess)
{
    SSL_SESSION *usesess = NULL;
    const SSL_CIPHER *cipher = NULL;

    if (psksess != NULL) {
        SSL_SESSION_up_ref(psksess);
        usesess = psksess;
    } else {
        long key_len;
        unsigned char *key = OPENSSL_hexstr2buf(psk_key, &key_len);

        if (key == NULL) {
            wpa_printf(MSG_DEBUG, "Could not convert PSK key '%s' to buffer\n",
                       psk_key);
            return 0;
        }

        /* We default to SHA-256 */
        cipher = SSL_CIPHER_find(s, tls13_aes128gcmsha256_id);
        if (cipher == NULL) {
            wpa_printf(MSG_DEBUG, "Error finding suitable ciphersuite\n");
            OPENSSL_free(key);
            return 0;
        }

        usesess = SSL_SESSION_new();
        if (usesess == NULL
                || !SSL_SESSION_set1_master_key(usesess, key, key_len)
                || !SSL_SESSION_set_cipher(usesess, cipher)
                || !SSL_SESSION_set_protocol_version(usesess, TLS1_3_VERSION)) {
            OPENSSL_free(key);
            goto err;
        }
        OPENSSL_free(key);
    }

    cipher = SSL_SESSION_get0_cipher(usesess);
    if (cipher == NULL)
        goto err;

    if (md != NULL && SSL_CIPHER_get_handshake_digest(cipher) != md) {
        /* PSK not usable, ignore it */
        *id = NULL;
        *idlen = 0;
        *sess = NULL;
        SSL_SESSION_free(usesess);
    } else {
        *sess = usesess;
        *id = (unsigned char *)psk_identity;
        *idlen = strlen(psk_identity);
    }

    return 1;

 err:
    SSL_SESSION_free(usesess);
    return 0;
}

static int psk_find_session_cb(SSL *ssl, const unsigned char *identity,
                               size_t identity_len, SSL_SESSION **sess){
    
	SSL_SESSION *tmpsess = NULL;
    unsigned char *key;
    long key_len;
    const SSL_CIPHER *cipher = NULL;

	if (strlen(psk_identity) != identity_len)
	{
		wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: PSK Identity length does not match.");
	    return 0;
	}

	if(memcmp(psk_identity, identity, identity_len) != 0)
	{
		wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: PSK Identity memory copy failed.");
	    return 0;
	}

	key = OPENSSL_hexstr2buf(psk_key, &key_len);

	if (key == NULL) {
        wpa_printf(MSG_ERROR, "Could not convert PSK key '%s' to buffer\n",
                   psk_key);
        return 0;
    }

	cipher = SSL_CIPHER_find(ssl, tls13_aes128gcmsha256_id);
    if (cipher == NULL) {
        wpa_printf(MSG_DEBUG, "Error finding suitable ciphersuite\n");
        OPENSSL_free(key);
        return 0;
    }

    tmpsess = SSL_SESSION_new();
    if (tmpsess == NULL
            || !SSL_SESSION_set1_master_key(tmpsess, key, key_len)
            || !SSL_SESSION_set_cipher(tmpsess, cipher)
            || !SSL_SESSION_set_protocol_version(tmpsess, SSL_version(ssl))) {
        OPENSSL_free(key);
        return 0;
    }
    OPENSSL_free(key);
    *sess = tmpsess;

    return 1;
}

static const char * openssl_content_type(int content_type)
{
	switch (content_type) {
	case 20:
		return "change cipher spec";
	case 21:
		return "alert";
	case 22:
		return "handshake";
	case 23:
		return "application data";
	case 24:
		return "heartbeat";
	case 256:
		return "TLS header info"; /* pseudo content type */
	case 257:
		return "inner content type"; /* pseudo content type */
	default:
		return "?";
	}
}


static const char * openssl_handshake_type(int content_type, const u8 *buf,
					   size_t len)
{
	if (content_type == 257 && buf && len == 1)
		return openssl_content_type(buf[0]);
	if (content_type != 22 || !buf || len == 0)
		return "";
	switch (buf[0]) {
	case 0:
		return "hello request";
	case 1:
		return "client hello";
	case 2:
		return "server hello";
	case 3:
		return "hello verify request";
	case 4:
		return "new session ticket";
	case 5:
		return "end of early data";
	case 6:
		return "hello retry request";
	case 8:
		return "encrypted extensions";
	case 11:
		return "certificate";
	case 12:
		return "server key exchange";
	case 13:
		return "certificate request";
	case 14:
		return "server hello done";
	case 15:
		return "certificate verify";
	case 16:
		return "client key exchange";
	case 20:
		return "finished";
	case 21:
		return "certificate url";
	case 22:
		return "certificate status";
	case 23:
		return "supplemental data";
	case 24:
		return "key update";
	case 254:
		return "message hash";
	default:
		return "?";
	}
}

static void tls_msg_cb(int write_p, int version, int content_type,
		       const void *buf, size_t len, SSL *ssl, void *arg)
{
	const u8 *pos = buf;

	if (write_p == 2) {
		wpa_printf(MSG_DEBUG,
			   "OpenSSL: session ver=0x%x content_type=%d",
			   version, content_type);
		wpa_hexdump_key(MSG_MSGDUMP, "OpenSSL: Data", buf, len);
		return;
	}

	wpa_printf(MSG_DEBUG, "OpenSSL: %s ver=0x%x content_type=%d (%s/%s)",
		   write_p ? "TX" : "RX", version, content_type,
		   openssl_content_type(content_type),
		   openssl_handshake_type(content_type, buf, len));
	wpa_hexdump_key(MSG_MSGDUMP, "OpenSSL: Message", buf, len);
	if (content_type == 24 && len >= 3 && pos[0] == 1) {
		size_t payload_len = WPA_GET_BE16(pos + 1);
        if (payload_len + 3 > len) {
			wpa_printf(MSG_ERROR, "OpenSSL: Heartbeat attack detected");			
		}
	}
}

static void set_psk(const u8 *data){

    psk_key = (char*) data;
    wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Setting the psk as: %s", data);
}

static const char * eap_tls_state_txt(int state)
{
	switch (state) {
	case START:
		return "START";
	case CONTINUE:
		return "CONTINUE";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "Unknown?!";
	}
}

static void eap_tls_state(struct eap_tls_psk_server_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: %s -> %s",
		   eap_tls_state_txt(data->state),
		   eap_tls_state_txt(state));
	data->state = state;
	///if (state == FAILURE)
		//tls_connection_remove_session(data->ssl.conn);
		
}

static int eap_server_tls_process_cont(struct eap_tls_psk_server_data *data,
				       const u8 *buf, size_t len)
{
	/* Process continuation of a pending message */
	if (len > wpabuf_tailroom(data->tls_in)) {
		wpa_printf(MSG_DEBUG, "SSL: Fragment overflow");
		return -1;
	}

	wpabuf_put_data(data->tls_in, buf, len);
	wpa_printf(MSG_DEBUG, "SSL: Received %lu bytes, waiting for %lu "
		   "bytes more", (unsigned long) len,
		   (unsigned long) wpabuf_tailroom(data->tls_in));

	return 0;
}

static int eap_server_tls_process_fragment(struct eap_tls_psk_server_data *data,
					   u8 flags, u32 message_length,
					   const u8 *buf, size_t len)
{
	/* Process a fragment that is not the last one of the message */
	if (data->tls_in == NULL && !(flags & EAP_TLS_FLAGS_LENGTH_INCLUDED)) {
		wpa_printf(MSG_DEBUG, "SSL: No Message Length field in a "
			   "fragmented packet");
		return -1;
	}

	if (data->tls_in == NULL) {
		/* First fragment of the message */

		/* Limit length to avoid rogue peers from causing large
		 * memory allocations. */
		if (message_length > 65536) {
			wpa_printf(MSG_INFO, "SSL: Too long TLS fragment (size"
				   " over 64 kB)");
			return -1;
		}

		if (len > message_length) {
			wpa_printf(MSG_INFO, "SSL: Too much data (%d bytes) in "
				   "first fragment of frame (TLS Message "
				   "Length %d bytes)",
				   (int) len, (int) message_length);
			return -1;
		}

		data->tls_in = wpabuf_alloc(message_length);
		if (data->tls_in == NULL) {
			wpa_printf(MSG_DEBUG, "SSL: No memory for message");
			return -1;
		}
		wpabuf_put_data(data->tls_in, buf, len);
		wpa_printf(MSG_DEBUG, "SSL: Received %lu bytes in first "
			   "fragment, waiting for %lu bytes more",
			   (unsigned long) len,
			   (unsigned long) wpabuf_tailroom(data->tls_in));
	}

	return 0;
}

static void eap_server_tls_psk_free_in_buf(struct eap_tls_psk_server_data *data)
{
	if (data->tls_in != &data->tmpbuf)
		wpabuf_free(data->tls_in);
	data->tls_in = NULL;
}

static void tls_show_errors(int level, const char *func, const char *txt)
{
	unsigned long err;

	wpa_printf(level, "OpenSSL: %s - %s %s",
		   func, txt, ERR_error_string(ERR_get_error(), NULL));

	while ((err = ERR_get_error())) {
		wpa_printf(MSG_INFO, "OpenSSL: pending error: %s",
			   ERR_error_string(err, NULL));
	}
}


// void tls_remove_connection(struct eap_tls_psk_server_data *data)
// {
// 	SSL_SESSION *sess;

// 	sess = SSL_get_session(data->ssl);
// 	if (!sess)
// 		return;
// 	SSL_CTX_remove_session(conn->ssl_ctx, sess)
// }