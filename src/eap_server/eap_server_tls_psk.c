#include "includes.h"

#include "common.h"
#include "eap_i.h"
#include "eap_tls_common.h"
#include "crypto/tls.h"
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <eap_common/eap_tls_psk_common.h>
#include "eap_common/eap_tls_psk_common.c"

// End Section: Common Methods.


static void * eap_tls_psk_init(struct eap_sm *sm)
{
	struct eap_tls_psk_server_data *data;
	const SSL_METHOD *method = TLS_method();

	data = os_zalloc(sizeof(*data));

	if (data == NULL)
		return NULL;

	data->state = START;
	data->eap_type = EAP_TYPE_TLS_PSK;

	//intialize the ssl ctx object
    data->ctx = SSL_CTX_new(method);
    //Set the version to always be 1.3
    if(SSL_CTX_set_min_proto_version(data->ctx, TLS1_3_VERSION) != 1){
        wpa_printf(MSG_INFO, "EAP-TLS-PSK: Cannot set TLS 1.3");
        return NULL;
    }

	return data;
}

static void eap_tls_psk_reset(struct eap_sm *sm, void *priv)
{
	struct eap_tls_psk_server_data *data = priv;
	if (data == NULL)
		return;
	SSL_CTX_free(data->ctx);
	os_free(data);
}

static struct wpabuf * eap_tls_psk_req_build(struct eap_sm *sm,
					   struct eap_tls_psk_server_data *data, u8 id)
{
	struct wpabuf *req;
	u8 flags;
	size_t send_len, plen;

	wpa_printf(MSG_DEBUG, "SSL: Generating Request");

	req = eap_tls_msg_alloc(data->eap_type, 1, EAP_CODE_REQUEST, id);
	flags = 0;
	if(req == NULL) 
	{
		wpa_printf(MSG_ERROR, "EAP-TLS-PSK: Failed to allocate memory for request");
		eap_tls_state(data, FAILURE);
		return NULL;
	}

	wpabuf_put_u8(req, EAP_TLS_FLAGS_START);

	eap_tls_state(data, CONTINUE);

	return req;

}

static struct wpabuf * eap_tls_psk_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_tls_psk_server_data *data = priv;
	struct wpabuf *res;

	return eap_tls_psk_req_build(sm, data, id);
}

static Boolean eap_tls_psk_check(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	struct eap_tls_psk_server_data *data = priv;
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, data->eap_type,
				       respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-TLS: Invalid frame");
		return TRUE;
	}

	return FALSE;
}


static int eap_server_tls_psk_reassemble(struct eap_tls_psk_server_data *data, u8 flags,
				     const u8 **pos, size_t *left)
{
	unsigned int tls_msg_len = 0;
	const u8 *end = *pos + *left;

	wpa_hexdump(MSG_MSGDUMP, "SSL: Received data", *pos, *left);

	if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
		if (*left < 4) {
			wpa_printf(MSG_INFO, "SSL: Short frame with TLS "
				   "length");
			return -1;
		}
		tls_msg_len = WPA_GET_BE32(*pos);
		wpa_printf(MSG_DEBUG, "SSL: TLS Message Length: %d",
			   tls_msg_len);
		*pos += 4;
		*left -= 4;

		if (*left > tls_msg_len) {
			wpa_printf(MSG_INFO, "SSL: TLS Message Length (%d "
				   "bytes) smaller than this fragment (%d "
				   "bytes)", (int) tls_msg_len, (int) *left);
			return -1;
		}
	}

	wpa_printf(MSG_DEBUG, "SSL: Received packet: Flags 0x%x "
		   "Message Length %u", flags, tls_msg_len);

	if (data->ssl_state == WAIT_FRAG_ACK) {
		if (*left != 0) {
			wpa_printf(MSG_DEBUG, "SSL: Unexpected payload in "
				   "WAIT_FRAG_ACK state");
			return -1;
		}
		wpa_printf(MSG_DEBUG, "SSL: Fragment acknowledged");
		return 1;
	}

	if (data->tls_in &&
	    eap_server_tls_process_cont(data, *pos, end - *pos) < 0)
		return -1;

	if (flags & EAP_TLS_FLAGS_MORE_FRAGMENTS) {
		if (eap_server_tls_process_fragment(data, flags, tls_msg_len,
						    *pos, end - *pos) < 0)
			return -1;

		data->state = FRAG_ACK;
		return 1;

	}

	if (data->state == FRAG_ACK) {
		wpa_printf(MSG_DEBUG, "SSL: All fragments received");
		data->state = MSG;
	}

	if (data->tls_in == NULL) {
		/* Wrap unfragmented messages as wpabuf without extra copy */
		wpabuf_set(&data->tmpbuf, *pos, end - *pos);
		data->tls_in = &data->tmpbuf;
	}

	return 0;
}

static void eap_tls_psk_process(struct eap_sm *sm, void *priv, struct wpabuf *respData)
{
	struct eap_tls_psk_server_data *data = priv;
	const struct wpabuf *buf;
	const u8 *pos;
	size_t len;
	u8 flags;
	
	pos = eap_hdr_validate(EAP_VENDOR_IETF, data->eap_type, respData,
				       &len);
	//Refactor this
	if(pos == NULL || len < 1){
		
	}else{
		flags = *pos++;
		len--;
	} 

	wpa_printf(MSG_DEBUG, "SSL: Received packet(len=%lu) - Flags 0x%02x",
		   (unsigned long) wpabuf_len(respData), flags);

	wpa_printf(MSG_INFO, "EAP-TLS-PSK: We are coming here.");
}

static void eap_tls_psk_isDone(struct eap_sm *sm, void *priv)
{
}

static void eap_tls_psk_getKey(struct eap_sm *sm, void *priv)
{
}


static void eap_tls_psk_isSuccess(struct eap_sm *sm, void *priv)
{
}


static void eap_tls_psk_get_emsk(struct eap_sm *sm, void *priv)
{
}


static void eap_tls_psk_get_session_id(struct eap_sm *sm, void *priv)
{
}

int eap_server_tls_psk_register(void)
{
	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_TLS_PSK, "TLS_PSK");
	if (eap == NULL)
		return -1;

	eap->init = eap_tls_psk_init;
	eap->reset = eap_tls_psk_reset;
	eap->buildReq = eap_tls_psk_buildReq;
	eap->check = eap_tls_psk_check;
	eap->process = eap_tls_psk_process;
	eap->isDone = eap_tls_psk_isDone;
	eap->getKey = eap_tls_psk_getKey;
	eap->isSuccess = eap_tls_psk_isSuccess;
	eap->get_emsk = eap_tls_psk_get_emsk;
	eap->getSessionId = eap_tls_psk_get_session_id;

	return eap_server_method_register(eap);
}