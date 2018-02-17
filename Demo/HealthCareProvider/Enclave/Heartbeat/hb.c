#include "../demo_enclave.h"
#include "../demo_enclave_t.h"

extern uint8_t hb_active;

sgx_status_t ecall_start_heartbeat(void){
  ocall_print("testing enclave function: ecall_start_heartbeat()");

  sgx_status_t ret = SGX_SUCCESS;

  hb_active = STATUS_HB_ACTIVE;

  return ret;
}

sgx_status_t ecall_end_heartbeat(void){
  ocall_print("testing enclave function: ecall_end_heartbeat()");

  sgx_status_t ret = SGX_SUCCESS;

  hb_active = STATUS_HB_INACTIVE;

  return ret;

}
