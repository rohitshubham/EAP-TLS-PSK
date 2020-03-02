#include <stdio.h>
#include "common.h"
#include "eap_i.h"
#include "eap_tls_common.h"

#define EAP_TLS_PSK_SHARED_KEY_LEN 16

struct eap_tls_psk_data {
    struct eap_ssl_data ssl;
    u8 *psk;
    u8 eap_type;
};


/**
 * eap_tls_psk_init :  initialize the eap tls-psk method 
 * @sm : eap statemachine context
 * Returns : eap tls-psk peer context
 **/
static void * eap_tls_psk_init(struct eap_sm *sm){
    struct eap_tls_psk_data *data;
    size_t psk_len;

    data = os_zalloc(sizeof(*data));
   	if (data == NULL)
		return NULL;


    data->eap_type = EAP_TYPE_TLS_PSK;
    data->psk = eap_get_config_password(sm, &psk_len);

    if (!data->psk || psk_len != EAP_TLS_PSK_SHARED_KEY_LEN) {
		wpa_printf(MSG_INFO, "EAP-TLS-PSK: 16-octet pre-shared key not "
			   "configured");
		return NULL;
	}    
    return data;    
}



static void * eap_tls_psk_deinit(struct eap_sm * sm, void * priv){
	struct eap_tls_psk_data *data = priv;
    eap_peer_tls_ssl_deinit(sm, &data->ssl);
	bin_clear_free(data, sizeof(*data));
}


static void * eap_tls_psk_process(struct eap_sm * sm, void * priv, struct eap_method_ret *ret, const struct wpabuf *reqData){

    struct eap_tls_psk_data *data = priv;
    const u8 *pos;
    u8 flags;
    size_t len;
    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TLS_PSK, reqData, &len);

    if (pos == NULL) {
		ret->ignore = TRUE;
		return NULL;
	}
    wpa_printf(MSG_INFO, "EAP-TLS-PSK: We are here now ");
    wpa_printf(MSG_DEBUG, "EAP_TLS_PSK: %d ", len);
    //pos = eap_peer_tls_process_init(sm, &data->ssl, data->eap_type, ret, reqData, &left, &flags);

}

static void * eap_tls_psk_isKeyAvailable(struct eap_sm * sm, void * priv){

}

static void * eap_tls_psk_getKey(struct eap_sm * sm, void * priv){

}

static void * eap_tls_psk_get_emsk(struct eap_sm * sm, void * priv){

}

static void * eap_tls_psk_get_session_id(struct eap_sm * sm, void * priv){

}

static void * eap_tls_psk_has_reauth_data(struct eap_sm * sm, void * priv){

}

static void * eap_tls_psk_init_for_reauth(struct eap_sm * sm, void * priv){

}

static void * eap_tls_psk_deinit_for_reauth(struct eap_sm * sm, void * priv){

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