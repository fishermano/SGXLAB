#ifndef DEMO_ENCLAVE_H
#define DEMO_ENCLAVE_H


#include <stdint.h>

#define DEVICE_KEY_MAX_NUM 20
#define SECRET_DATA_SIZE 8

typedef struct key_set_t{
  uint8_t key_num;
  uint8_t device_keys[DEVICE_KEY_MAX_NUM][16];
}key_set_t;

typedef struct dev_data_t{
  uint8_t size;
  uint8_t data[SECRET_DATA_SIZE];
}dev_data_t;

typedef enum _hb_status{
  STATUS_HB_INACTIVE,
  STATUS_HB_ACTIVE,
}hb_status;

#endif
