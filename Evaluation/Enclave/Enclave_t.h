#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void ecall_decrypt();
sgx_status_t ecall_evaluate_decryption(uint8_t* p_files, uint32_t file_number, uint32_t total_size);
sgx_status_t ecall_evaluate_encryption(uint32_t file_number);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_print_int(int num);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
