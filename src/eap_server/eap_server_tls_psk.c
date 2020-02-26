#include "includes.h"

#include "common.h"
#include "eap_i.h"
#include "eap_tls_common.h"
#include "crypto/tls.h"


struct eap_tls_psk_data {
    struct eap_ssl_data ssl;
	enum { START, CONTINUE, SUCCESS, FAILURE } state;
	int established;
    u8 *psk;
	u8 eap_type;
};

static void eap_tls_reset(struct eap_sm *sm, void *priv)
{
	struct eap_tls_psk_data *data = priv;
	if (data == NULL)
		return;
	eap_server_tls_ssl_deinit(sm, &data->ssl);
	os_free(data);
}


static void * eap_tls_psk_init(struct eap_sm *sm)
{
	struct eap_tls_psk_data *data;

	data = os_zalloc(sizeof(*data));

	if (data == NULL)
		return NULL;
	data->state = START;

	if (eap_server_tls_ssl_init(sm, &data->ssl, 1, EAP_TYPE_TLS)) {
		wpa_printf(MSG_INFO, "EAP-TLS-PSK: Failed to initialize SSL.");
		eap_tls_reset(sm, data);
		return NULL;
	}

	data->eap_type = EAP_TYPE_TLS;
	wpa_printf(MSG_INFO, "EAP-TLS-PSK: This is working now!.");
	return data;

}

static void eap_tls_psk_reset(struct eap_sm *sm, void *priv)
{
}

static struct wpabuf * eap_tls_psk_buildReq(struct eap_sm *sm, void *priv)
{
}

static void eap_tls_psk_check(struct eap_sm *sm, void *priv)
{
}

static void eap_tls_psk_process(struct eap_sm *sm, void *priv)
{
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