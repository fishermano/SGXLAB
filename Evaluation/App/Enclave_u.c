#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_evaluate_decryption_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_files;
	uint32_t ms_file_number;
	uint32_t ms_total_size;
} ms_ecall_evaluate_decryption_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_int_t {
	int ms_num;
} ms_ocall_print_int_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_int(void* pms)
{
	ms_ocall_print_int_t* ms = SGX_CAST(ms_ocall_print_int_t*, pms);
	ocall_print_int(ms->ms_num);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_print_int,
	}
};
sgx_status_t ecall_decrypt(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_evaluate_decryption(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_files, uint32_t file_number, uint32_t total_size)
{
	sgx_status_t status;
	ms_ecall_evaluate_decryption_t ms;
	ms.ms_p_files = p_files;
	ms.ms_file_number = file_number;
	ms.ms_total_size = total_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

