#include <stdio.h>
#include "common.h"
#include "eap_i.h"

int eap_peer_tls_psk_register(void){
    struct eap_method* eap = NULL;

    eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION, EAP_VENDOR_IETF, EAP_TYPE_TLS_PSK, "TLS-PSK");

    if (eap == NULL) {
        return -1;
    }

    //Define the EAP TLS PSK state machines here?

    return eap_peer_method_register(eap);
}