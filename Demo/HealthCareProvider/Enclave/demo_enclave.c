/*
  this file defines enclave global parameters
*/

#include <stdint.h>

#include "demo_enclave.h"

// secret shared key between demo_app and trusted broker
// during remote attestation
uint8_t secret_share_key[16] = {0};
// uncovered
uint8_t u_secret_share_key[16] = {0};

// device keys received from trusted broker
key_set_t key_set = {0};
