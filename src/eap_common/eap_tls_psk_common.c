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



// TLS PSK Session callback . Builds a new 
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
            wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Could not convert PSK key '%s' to buffer\n",
                       psk_key);
            return 0;
        }

        /* We default to SHA-256 */
        cipher = SSL_CIPHER_find(s, tls13_aes128gcmsha256_id);
        if (cipher == NULL) {
            wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Error finding suitable ciphersuite\n");
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

	//temperory fixed psk
	data = "0533c95c9ecc310ee07cb70a316c45448487c1f70bbea99fe6616f3348305677";
    psk_key = (char*) data;
    wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Setting the psk as: %s", psk_key);
}