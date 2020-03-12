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
					   struct eap_tls_psk_data *data, u8 id)
{
	struct wpabuf *req;
	req = eap_tls_msg_alloc(data->eap_type, 1, EAP_CODE_REQUEST, id);

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
	struct eap_tls_psk_data *data = priv;
	struct wpabuf *res;

	return eap_tls_psk_req_build(sm, data, id);
}

static Boolean eap_tls_psk_check(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	struct eap_tls_psk_data *data = priv;
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

static void eap_tls_psk_process(struct eap_sm *sm, void *priv)
{
	struct eap_tls_data *data = priv;
	const struct wpabuf *buf;
	const u8 *pos;
	
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