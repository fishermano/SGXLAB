/*
  this file defines enclave global parameters
*/

#include <stdint.h>
#include "string.h"

#include "sgx_tae_service.h"

#include "demo_enclave.h"

//heartbeat mechanism status
sgx_time_t hb_state = NULL;
sgx_time_source_nonce_t nonce = {0};

// secret shared key between demo_app and trusted broker
// during remote attestation
uint8_t shared_key[16] = {0};
// uncovered
uint8_t u_shared_key[16] = {0};

// device keys received from trusted broker
key_set_t *device_keys = NULL;

// maximum counter of received heartbeat
uint8_t r_max = 0;
