#include "../demo_enclave_t.h"

void ecall_perform_fun_1(void){
  ocall_print("testing enclave function: ecall_perform_fun_1()");
  return;
}

void ecall_perform_fun_2(void){
  ocall_print("testing enclave function: ecall_perform_fun_2()");
  return;
}
