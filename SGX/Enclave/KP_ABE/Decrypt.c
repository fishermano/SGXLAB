
#include "../Enclave_t.h"

#include "gmp.h"
//#include "pbc.h"
#include "calculation.h"

void ecall_decrypt(void){

 ocall_print("Hell SGX...");

 int a = 5;
 int b = 8;
 int c = plus(a, b);
 int d = minus(a, b);
 ocall_print_int(c);
 ocall_print_int(d);

 sgx_status_t ret = SGX_ERROR_UNEXPECTED;
 int size = 25;
 int res = 0;
 ret = ocall_fetch_data(&res, size);
 if (ret != SGX_SUCCESS){
   abort();
 }else{
   if (res == 25){
     ocall_print("Fetching Data Size: 25");
   }
 }

 return;
}
