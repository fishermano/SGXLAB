/*
  this file defines enclave global parameters
*/

#include <stdint.h>

#include "demo_enclave.h"

// secret shared key between demo_app and trusted broker

uint8_t secret_share_key[8] = {0};

// device keys received from trusted broker
uint8_t device_keys[DEVICE_KEY_MAX_NUM][8] = {0};
