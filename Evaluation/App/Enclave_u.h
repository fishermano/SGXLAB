#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

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
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_int, (int num));

sgx_status_t ecall_decrypt(sgx_enclave_id_t eid);
sgx_status_t ecall_evaluate_decryption(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_files, uint32_t file_number, uint32_t total_size);
sgx_status_t ecall_evaluate_encryption(sgx_enclave_id_t eid, sgx_status_t* retval, uint32_t file_number);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
