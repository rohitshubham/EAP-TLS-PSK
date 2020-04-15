#include "includes.h"

#include "common.h"
#include "eap_i.h"
#include "crypto/tls.h"
#include "eap_tls_common.h"



struct eap_tls_psk_data {
	struct eap_ssl_data ssl;
	u8 eap_type;
	enum { START, CONTINUE, SUCCESS, FAILURE } state;
	int established;
	int phase2;

};

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

static void eap_tls_psk_reset(struct eap_sm *sm, void *priv)
{
	struct eap_tls_psk_data *data = priv;
	if (data == NULL)
		return;
	eap_server_tls_ssl_deinit(sm, &data->ssl);
	os_free(data);
}

static void eap_tls_psk_state(struct eap_tls_psk_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: %s -> %s",
		   eap_tls_state_txt(data->state),
		   eap_tls_state_txt(state));
	data->state = state;
	if (state == FAILURE)
		tls_connection_remove_session(data->ssl.conn);
}

static void eap_tls_psk_valid_session(struct eap_sm *sm, struct eap_tls_psk_data *data)
{
	struct wpabuf *buf;

	if (!sm->cfg->tls_session_lifetime)
		return;

	buf = wpabuf_alloc(1);
	if (!buf)
		return;
	wpabuf_put_u8(buf, data->eap_type);
	tls_connection_set_success_data(data->ssl.conn, buf);
}


static void * eap_tls_psk_init(struct eap_sm *sm)
{
	struct eap_tls_psk_data *data;

	data = os_zalloc(sizeof(*data));

	if (data == NULL)
		return NULL;

	data->state = START;
	data->eap_type = EAP_TYPE_TLS_PSK;

	if (eap_server_tls_psk_ssl_init(sm, &data->ssl, 0, EAP_TYPE_TLS_PSK)) {
		wpa_printf(MSG_INFO, "EAP-TLS-PSK: Failed to initialize SSL.");
		eap_tls_psk_reset(sm, data);
		return NULL;
	}

	data->phase2 = sm->init_phase2;

	return data;
}

static struct wpabuf * eap_tls_psk_build_start(struct eap_sm *sm,
					   struct eap_tls_psk_data *data, u8 id)
{
	struct wpabuf *req;


	req = eap_tls_msg_alloc(data->eap_type, 1, EAP_CODE_REQUEST, id);
	if(req == NULL) 
	{
		wpa_printf(MSG_ERROR, "EAP-TLS-PSK: Failed to allocate memory for request");
		eap_tls_psk_state(data, FAILURE);
		return NULL;
	}

	wpabuf_put_u8(req, EAP_TLS_FLAGS_START);

	eap_tls_psk_state(data, CONTINUE);

	return req;

}

static struct wpabuf * eap_tls_psk_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_tls_psk_data *data = priv;
	struct wpabuf *res;

	if (data->ssl.state == FRAG_ACK) {
		return eap_server_tls_build_ack(id, data->eap_type, 0);
	}

	//ToDO: Check what's going here
	if (data->ssl.state == WAIT_FRAG_ACK) {
		res = eap_server_tls_build_msg(&data->ssl, data->eap_type, 0,
					       id);
		goto check_established;
	}

	switch (data->state) {
	case START:
		res = eap_tls_psk_build_start(sm, data, id);
		return res;
	case CONTINUE:		
		if (tls_connection_established(sm->cfg->ssl_ctx,
					       data->ssl.conn))
			data->established = 1;
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: %s - unexpected state %d",
			   __func__, data->state);
		return NULL;
	}
	res = eap_server_tls_build_msg(&data->ssl, data->eap_type, 0, id);

	

check_established:
	if (data->established && data->ssl.state != WAIT_FRAG_ACK) {
		/* TLS handshake has been completed and there are no more
		 * fragments waiting to be sent out. */
		wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Done");
		eap_tls_psk_state(data, SUCCESS);
		eap_tls_psk_valid_session(sm, data);
		if (sm->serial_num) {
			char user[128];
			int user_len;

			user_len = os_snprintf(user, sizeof(user), "cert-%s",
					       sm->serial_num);
			if (eap_user_get(sm, (const u8 *) user, user_len,
					 data->phase2) < 0)
				wpa_printf(MSG_DEBUG,
					   "EAP-TLS-PSK: No user entry found based on the serial number of the client certificate ");
			else
				wpa_printf(MSG_DEBUG,
					   "EAP-TLS-PSK: Updated user entry based on the serial number of the client certificate ");
		}
	}

	return res;

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
		wpa_printf(MSG_INFO, "EAP-TLS-PSK: Invalid frame");
		return TRUE;
	}

	return FALSE;
}

static void eap_tls_psk_process_msg(struct eap_sm *sm, void *priv,
				const struct wpabuf *respData)
{
	struct eap_tls_psk_data *data = priv;

	if (data->state == SUCCESS && wpabuf_len(data->ssl.tls_in) == 0) {
		wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Client acknowledged final TLS "
			   "handshake message");
		return;
	}
	if (eap_server_tls_phase1(sm, &data->ssl) < 0) {
		eap_tls_psk_state(data, FAILURE);
		return;
	}

	if (data->ssl.tls_v13 &&
	    tls_connection_established(sm->cfg->ssl_ctx, data->ssl.conn)) {
		struct wpabuf *plain, *encr;

		wpa_printf(MSG_DEBUG,
			   "EAP-TLS-PSK: Send empty application data to indicate end of exchange");
		/* FIX: This should be an empty application data based on
		 * draft-ietf-emu-eap-tls13-05, but OpenSSL does not allow zero
		 * length payload (SSL_write() documentation explicitly
		 * describes this as not allowed), so work around that for now
		 * by sending out a payload of one octet. Hopefully the draft
		 * specification will change to allow this so that no crypto
		 * library changes are needed. */
		plain = wpabuf_alloc(1);
		if (!plain)
			return;
		wpabuf_put_u8(plain, 0);
		encr = eap_server_tls_encrypt(sm, &data->ssl, plain);
		wpabuf_free(plain);
		if (!encr)
			return;
		if (wpabuf_resize(&data->ssl.tls_out, wpabuf_len(encr)) < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-TLS-PSK: Failed to resize output buffer");
			wpabuf_free(encr);
			return;
		}
		wpabuf_put_buf(data->ssl.tls_out, encr);
		wpa_hexdump_buf(MSG_DEBUG,
				"EAP-TLS-PSK: Data appended to the message", encr);
		wpabuf_free(encr);
	}
	return;
}

static void eap_tls_psk_process(struct eap_sm *sm, void *priv, struct wpabuf *respData)
{
	struct eap_tls_psk_data *data = priv;
	const struct wpabuf *buf;
	const u8 *pos;

	if (eap_server_tls_process(sm, &data->ssl, respData, data,
				   data->eap_type, NULL, eap_tls_psk_process_msg) <
	    0) {
		eap_tls_psk_state(data, FAILURE);
		return;
	}

	if (!tls_connection_established(sm->cfg->ssl_ctx, data->ssl.conn) ||
	    !tls_connection_resumed(sm->cfg->ssl_ctx, data->ssl.conn))
			return;
	
	wpa_printf(MSG_INFO, "EAP-TLS-PSK: We are coming here.");

	buf = tls_connection_get_success_data(data->ssl.conn);
	if (!buf || wpabuf_len(buf) < 1) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TLS-PSK: No success data in resumed session - reject attempt");
		eap_tls_psk_state(data, FAILURE);
		return;
	}

	pos = wpabuf_head(buf);
	if (*pos != data->eap_type) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TLS-PSK: Resumed session for another EAP type (%u) - reject attempt",
			   *pos);
		eap_tls_psk_state(data, FAILURE);
		return;
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-TLS-PSK: Resuming previous session");
	eap_tls_psk_state(data, SUCCESS);
	tls_connection_set_success_data_resumed(data->ssl.conn);

	return;
}

static Boolean eap_tls_psk_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_tls_psk_data *data = priv;
	return data->state == SUCCESS || data->state == FAILURE;

}

static u8 * eap_tls_psk_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_tls_psk_data *data = priv;
	u8 *eapKeyData;
	const char *label;
	const u8 eap_tls13_context[] = { EAP_TYPE_TLS_PSK };
	const u8 *context = NULL;
	size_t context_len = 0;

	if (data->state != SUCCESS)
		return NULL;

	label = "EXPORTER_EAP_TLS_PSK_Key_Material";
	context = eap_tls13_context;
	context_len = 1;
	
	eapKeyData = eap_server_tls_derive_key(sm, &data->ssl, label,
					       context, context_len,
					       EAP_TLS_KEY_LEN + EAP_EMSK_LEN);
	if (eapKeyData) {
		*len = EAP_TLS_KEY_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-TLS-PSK: Derived key",
			    eapKeyData, EAP_TLS_KEY_LEN);
		os_memset(eapKeyData + EAP_TLS_KEY_LEN, 0, EAP_EMSK_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Failed to derive key");
	}

	return eapKeyData;

}


static Boolean eap_tls_psk_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_tls_psk_data *data = priv;
	return data->state == SUCCESS;

}


static u8 * eap_tls_psk_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{

	struct eap_tls_psk_data *data = priv;
	u8 *eapKeyData, *emsk;
	const char *label;
	const u8 eap_tls13_context[] = { EAP_TYPE_TLS_PSK };
	const u8 *context = NULL;
	size_t context_len = 0;

	if (data->state != SUCCESS)
		return NULL;

	if (data->ssl.tls_v13) {
		label = "EXPORTER_EAP_TLS_Key_Material";
		context = eap_tls13_context;
		context_len = 1;
	} else {
		label = "client EAP encryption";
	}
	eapKeyData = eap_server_tls_derive_key(sm, &data->ssl, label,
					       context, context_len,
					       EAP_TLS_KEY_LEN + EAP_EMSK_LEN);
	if (eapKeyData) {
		emsk = os_malloc(EAP_EMSK_LEN);
		if (emsk)
			os_memcpy(emsk, eapKeyData + EAP_TLS_KEY_LEN,
				  EAP_EMSK_LEN);
		bin_clear_free(eapKeyData, EAP_TLS_KEY_LEN + EAP_EMSK_LEN);
	} else
		emsk = NULL;

	if (emsk) {
		*len = EAP_EMSK_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-TLS-PSK: Derived EMSK",
			    emsk, EAP_EMSK_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-TLS-PSK: Failed to derive EMSK");
	}

	return emsk;
}


static u8 * eap_tls_psk_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_tls_psk_data *data = priv;

	if (data->state != SUCCESS)
		return NULL;

	return eap_server_tls_derive_session_id(sm, &data->ssl, EAP_TYPE_TLS_PSK,
						len);
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