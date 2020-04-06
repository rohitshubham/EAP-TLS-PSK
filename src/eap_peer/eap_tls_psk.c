#include "includes.h"

#include <stdio.h>
#include "common.h"
#include "eap_i.h"
#include "eap_tls_common.h"
#include "crypto/tls.h"
#include "eap_config.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


struct eap_tls_psk_data {
	struct eap_ssl_data ssl;
	void *ssl_ctx;
	struct wpabuf *pending_resp;
	u8 *session_id;
	u8 eap_type;
	u8 *key_data;
	size_t id_len;	
};

static void eap_tls_psk_deinit(struct eap_sm * sm, void * priv){
	struct eap_tls_psk_data *data = priv;
	bin_clear_free(data, sizeof(*data));
}


/**
 * eap_tls_psk_init :  initialize the eap tls-psk method 
 * @sm : eap statemachine context
 * Returns : eap tls-psk peer context
 **/
static void * eap_tls_psk_init(struct eap_sm *sm){
    struct eap_tls_psk_data *data;
	struct eap_peer_config *config = eap_get_config(sm);

    data = os_zalloc(sizeof(*data));
   	if (data == NULL)
		return NULL;

	data->ssl_ctx = sm->init_phase2 && sm->ssl_ctx2 ? sm->ssl_ctx2 :
		sm->ssl_ctx;

    
	if (eap_peer_tls_psk_ssl_init(sm, &data->ssl, config, EAP_TYPE_TLS_PSK)) {
		wpa_printf(MSG_INFO, "EAP-TLS-PSK: Failed to initialize SSL.");
		eap_tls_psk_deinit(sm, data);
		return NULL;
	}

    data->eap_type = EAP_TYPE_TLS_PSK;

    return data;    
}

static struct wpabuf * eap_tls_psk_failure(struct eap_sm *sm,
				       struct eap_tls_psk_data *data,
				       struct eap_method_ret *ret, int res,
				       struct wpabuf *resp, u8 id)
{
	wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: TLS processing failed");

	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_FAIL;

	if (resp) {
		/*
		 * This is likely an alert message, so send it instead of just
		 * ACKing the error.
		 */
		return resp;
	}

	return eap_peer_tls_build_ack(id, data->eap_type, 0);
}



static struct wpabuf * eap_tls_psk_process(struct eap_sm * sm, void * priv, struct eap_method_ret *ret, const struct wpabuf *reqData){

    struct eap_tls_psk_data *data = priv;
    const u8 *pos;
    u8 id, flags;
    size_t left;
    struct wpabuf *resp = NULL;
	struct wpabuf msg;
	int res;

	pos = eap_peer_tls_process_init(sm, &data->ssl, data->eap_type, ret,
					reqData, &left, &flags);


    if (pos == NULL) 
		return NULL;

	id = eap_get_id(reqData);
	
	if (flags & EAP_TLS_FLAGS_START) {
		wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Start");
		left = 0; /* make sure that this frame is empty, even though it
			   * should always be, anyway */
	}
	wpa_printf(MSG_INFO, "EAP-TLS-PSK: Starting authentication");


	resp = NULL;
	wpabuf_set(&msg, pos, left);

	res = eap_peer_tls_process_helper(sm, &data->ssl, data->eap_type, 0,
					  id, &msg, &resp);

	if (res < 0) {
		return eap_tls_psk_failure(sm, data, ret, res, resp, id);
	}	

	if (res == 2) {
		/* Application data included in the handshake message (used by
		 * EAP-TLS 1.3 to indicate conclusion of the exchange). */
		wpa_hexdump_buf(MSG_DEBUG, "EAP-TLS: Received Application Data",
				resp);
		wpa_hexdump_buf(MSG_DEBUG, "EAP-TLS: Remaining tls_out data",
				data->ssl.tls_out);
		eap_peer_tls_reset_output(&data->ssl);
		/* Send an ACK to allow the server to complete exchange */
		res = 1;
	}
	
/* 
	if (tls_connection_established(data->ssl_ctx, data->ssl.conn))
		eap_tls_success(sm, data, ret);
 */
	if (res == 1) {
		wpabuf_free(resp);
		return eap_peer_tls_build_ack(id, data->eap_type, 0);
	}


	return resp;
}

static Boolean eap_tls_psk_isKeyAvailable(struct eap_sm * sm, void * priv){
	
	return FALSE;
}

static u8 * eap_tls_psk_getKey(struct eap_sm * sm, void * priv){
	return NULL;
}

static u8 * eap_tls_psk_get_emsk(struct eap_sm * sm, void * priv){
	return NULL;
}

static u8 * eap_tls_psk_get_session_id(struct eap_sm * sm, void * priv){
	return NULL;
}

static Boolean eap_tls_psk_has_reauth_data(struct eap_sm * sm, void * priv){
	return FALSE;
}

static void * eap_tls_psk_init_for_reauth(struct eap_sm * sm, void * priv){
	return NULL;
}

static void eap_tls_psk_deinit_for_reauth(struct eap_sm * sm, void * priv){
	return;
}

int eap_peer_tls_psk_register(void){
    struct eap_method *eap = NULL;

    eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION, EAP_VENDOR_IETF, EAP_TYPE_TLS_PSK, "TLS_PSK");

    if (eap == NULL) {
        return -1;
    }

    eap->init = eap_tls_psk_init;
    eap->deinit = eap_tls_psk_deinit;
    eap->process = eap_tls_psk_process;
    eap->isKeyAvailable = eap_tls_psk_isKeyAvailable;
    eap->getKey = eap_tls_psk_getKey;
    eap->get_emsk = eap_tls_psk_get_emsk;
    eap->getSessionId = eap_tls_psk_get_session_id;
    eap->has_reauth_data = eap_tls_psk_has_reauth_data;
    eap->init_for_reauth = eap_tls_psk_init_for_reauth;
    eap->deinit_for_reauth = eap_tls_psk_deinit_for_reauth;

    return eap_peer_method_register(eap);

}