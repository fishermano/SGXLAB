
#include "../Enclave_t.h"

#include "gmp.h"
//#include "pbc.h"
#include "calculation.h"

#include "mycrypto.h"

#include "string.h"

#define DATA_SIZE 1

uint8_t shared_key[16] = {
  0x72, 0xee, 0x30, 0xb0,
  0x1d, 0xd9, 0x11, 0x38,
  0x24, 0x11, 0x14, 0x3a,
  0xe2, 0xaa, 0x60, 0x38
};

struct file_t {
    uint8_t payload_size;
    uint8_t payload_tag[16];
    uint8_t payload[DATA_SIZE];
};

void ecall_decrypt(void){

 ocall_print("Hell SGX...");

 int a = 5;
 int b = 8;
 int c = plus(a, b);
 int d = minus(a, b);
 ocall_print_int(c);
 ocall_print_int(d);

 return;
}

sgx_status_t ecall_evaluate_decryption(uint8_t *p_files, uint32_t file_number, uint32_t total_size){

  // ocall_print("testing enclave function: ecall_evaluate_decryption()");
  // ocall_print_int(file_number);
  // ocall_print_int(total_size);

  sgx_status_t ret = SGX_SUCCESS;

  // size_t length = 8;
  // uint8_t input[8] = {
  //   0xf5, 0x5b, 0x56, 0xf0, 0xac, 0x7f, 0x78, 0x39};
  uint8_t output[DATA_SIZE];

  size_t add_len = 0;
  uint8_t *add = NULL;
  size_t iv_len = 12;
  uint8_t iv[12] = {0};

  uint8_t tag[16] = {0};
  size_t tag_len = 16;

  struct file_t *file = (struct file_t *)malloc(DATA_SIZE + 17);

  for(uint32_t i = 0; i < file_number; i++){
    memcpy(file, p_files, DATA_SIZE + 17);

    ret = decryption(shared_key,
      iv, iv_len,
      add, add_len,
      file->payload_tag, tag_len,
      file->payload, file->payload_size,
      output);

    // if(input[0] != output[0]){
    //   ocall_print("Decryption Error!");
    //   return OPERATION_FAIL;
    // }

    p_files = p_files + DATA_SIZE + 17;
  }

  return ret;
}
