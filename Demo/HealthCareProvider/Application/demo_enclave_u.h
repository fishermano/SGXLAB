#ifndef DEMO_ENCLAVE_U_H__
#define DEMO_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));

sgx_status_t ecall_init_ra(sgx_enclave_id_t eid);
sgx_status_t ecall_close_ra(sgx_enclave_id_t eid);
sgx_status_t ecall_verify_att_result_mac(sgx_enclave_id_t eid);
sgx_status_t ecall_put_secrets(sgx_enclave_id_t eid);
sgx_status_t ecall_create_sealed_policy(sgx_enclave_id_t eid);
sgx_status_t ecall_perform_sealed_policy(sgx_enclave_id_t eid);
sgx_status_t ecall_start_heartbeat(sgx_enclave_id_t eid);
sgx_status_t ecall_perform_fun_1(sgx_enclave_id_t eid);
sgx_status_t ecall_perform_fun_2(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
