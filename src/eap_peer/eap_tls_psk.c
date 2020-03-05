#include <stdio.h>
#include "common.h"
#include "eap_i.h"
#include "eap_tls_common.h"
#include <openssl/ssl.h>
#include<tls_openssl.h>

#define EAP_TLS_PSK_SHARED_KEY_LEN 16

struct eap_tls_psk_data {
    SSL_CTX *ctx;
    struct tls_connection *conn;
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
    struct eap_peer_config *config = eap_get_config(sm);
    const SSL_METHOD *method = TLS_method();

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

    //intialize the ssl ctx object
    data->ctx = SSL_CTX_new(method);
    //Set the version to always be 1.3
    if(SSL_CTX_set_min_proto_version(data->ctx, TLS1_3_VERSION) != 1){
        wpa_printf(MSG_INFO, "EAP-TLS-PSK: Cannot set TLS 1.3");
        return NULL;
    }

    return data;    
}



static void * eap_tls_psk_deinit(struct eap_sm * sm, void * priv){
	struct eap_tls_psk_data *data = priv;
	bin_clear_free(data, sizeof(*data));
}


static struct wpabuf * eap_tls_psk_process(struct eap_sm * sm, void * priv, struct eap_method_ret *ret, const struct wpabuf *reqData){

    struct eap_tls_psk_data *data = priv;
    const u8 *pos;
    u8 flags;
    size_t len;
    struct wpabuf *resp = NULL;
    SSL *con = NULL;
    struct wpabuf *out_data;

    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TLS_PSK, reqData, &len);

    if (pos == NULL) {
		ret->ignore = TRUE;
		return NULL;
	} 

    
    con = SSL_new(data->ctx);
    BIO *ssl_in, *ssl_out;

    ssl_in = BIO_new(BIO_s_mem());
	if (!ssl_in) {
		tls_show_errors(MSG_INFO, __func__,
				"Failed to create a new BIO for ssl_in");
		SSL_free(con);
		os_free(data->ctx);
		return NULL;
	}

    ssl_out = BIO_new(BIO_s_mem());
	if (!ssl_out) {
		tls_show_errors(MSG_INFO, __func__,
				"Failed to create a new BIO for ssl_out");
		SSL_free(con);
		BIO_free(ssl_in);
		os_free(data->ctx);
		return NULL;
	}

    SSL_set_bio(con, ssl_in, ssl_out);

    int res = SSL_connect(con);

    if (res != 1) {
		int err = SSL_get_error(con, res);
		if (err == SSL_ERROR_WANT_READ)
			wpa_printf(MSG_DEBUG, "SSL: SSL_connect - want "
				   "more data");
		else if (err == SSL_ERROR_WANT_WRITE)
			wpa_printf(MSG_DEBUG, "SSL: SSL_connect - want to "
				   "write");
		else {
			tls_show_errors(MSG_INFO, __func__, "SSL_connect");
			//conn->failed++;
		}
	}

    res = BIO_ctrl_pending(ssl_out);
    wpa_printf(MSG_DEBUG, "SSL: %d bytes pending from ssl_out", res);
    out_data = wpabuf_alloc(res);

    res = res == 0 ? 0 : BIO_read(ssl_out, wpabuf_mhead(out_data),
				      res);

    if (out_data == NULL) {
		wpa_printf(MSG_DEBUG, "SSL: Failed to allocate memory for "
			   "handshake output (%d bytes)", res);
		if (BIO_reset(ssl_out) < 0) {
			tls_show_errors(MSG_INFO, __func__,
					"BIO_reset failed");
		}
		return NULL;
	}

    if (res < 0) {
		tls_show_errors(MSG_INFO, __func__,
				"Handshake failed - BIO_read");
		if (BIO_reset(ssl_out) < 0) {
			tls_show_errors(MSG_INFO, __func__,
					"BIO_reset failed");
		}
		wpabuf_free(out_data);
		return NULL;
	}
	wpabuf_put(out_data, res);

    wpabuf_len(out_data);



    wpa_printf(MSG_INFO, "EAP-TLS-PSK: We are here now ");
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TLS_PSK, );
    return resp;

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