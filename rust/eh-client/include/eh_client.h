#ifndef EH_CLIENT_H
#define EH_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EH_OK              0
#define EH_NEED_OOB        1
#define EH_ERR_INVALID_ARG (-1)
#define EH_ERR_STATE       (-2)
#define EH_ERR_NETWORK     (-3)
#define EH_ERR_SERVER      (-4)
#define EH_ERR_SESSION     (-5)
#define EH_ERR_CODE        (-6)
#define EH_ERR_PACKAGE     (-7)
#define EH_ERR_PANIC       (-99)

typedef struct EhClient EhClient;

EhClient *eh_client_new(const char *config_json);

void eh_client_free(EhClient *client);

int eh_client_activate(EhClient *client, const char *oob_code);

int eh_client_establish(EhClient *client);

int eh_client_heartbeat(EhClient *client);

int eh_client_ensure_session(EhClient *client);

const char *eh_client_status_json(EhClient *client);

const char *eh_client_last_error(EhClient *client);

const char *eh_client_vm_seed(EhClient *client);

const uint8_t *eh_client_payload(EhClient *client, size_t *out_len);

#ifdef __cplusplus
} 
#endif

#endif 
