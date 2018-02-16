#include "../demo_enclave_t.h"

sgx_status_t ecall_perform_add_fun(uint8_t* p_secret_1, uint32_t secret_size_1, uint8_t* gcm_mac_1, uint8_t* p_secret_2, uint32_t secret_size_2, uint8_t* gcm_mac_2){
  ocall_print("testing enclave function: ecall_perform_fun_1()");

  sgx_status_t ret = SGX_SUCCESS;


  return ret;
}
