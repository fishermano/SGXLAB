/*
  this file defines enclave global parameters
*/

#include <stdint.h>
#include "string.h"

#include "demo_enclave.h"

//heartbeat mechanism status
uint8_t hb_state = STATUS_HB_INACTIVE;

// secret shared key between demo_app and trusted broker
// during remote attestation
uint8_t shared_key[16] = {0};
// uncovered
uint8_t u_shared_key[16] = {0};

// device keys received from trusted broker
key_set_t *device_keys = NULL;
