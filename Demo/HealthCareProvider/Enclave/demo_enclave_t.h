#ifndef DEMO_ENCLAVE_T_H__
#define DEMO_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void ecall_init_ra();
void ecall_close_ra();
void ecall_verify_att_result_mac();
void ecall_put_secrets();
void ecall_create_sealed_policy();
void ecall_perform_sealed_policy();
void ecall_start_heartbeat();
void ecall_perform_fun_1();
void ecall_perform_fun_2();

sgx_status_t SGX_CDECL ocall_print(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
