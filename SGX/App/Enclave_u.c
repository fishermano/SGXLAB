#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_int_t {
	int ms_num;
} ms_ocall_print_int_t;

typedef struct ms_ocall_fetch_data_t {
	int ms_retval;
	int ms_size;
} ms_ocall_fetch_data_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_fetch_data(void* pms)
{
	ms_ocall_fetch_data_t* ms = SGX_CAST(ms_ocall_fetch_data_t*, pms);
	ms->ms_retval = ocall_fetch_data(ms->ms_size);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_Enclave = {
	3,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_print_int,
		(void*)Enclave_ocall_fetch_data,
	}
};
sgx_status_t ecall_decrypt(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

