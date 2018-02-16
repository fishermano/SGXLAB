
#define DEVICE_KEY_MAX_NUM 20

typedef struct key_set_t{
  uint8_t key_num;
  uint8_t device_keys[DEVICE_KEY_MAX_NUM][16];
}key_set_t;
