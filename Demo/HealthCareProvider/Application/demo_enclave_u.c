#include "demo_enclave_u.h"
#include <errno.h>

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL demo_enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_demo_enclave = {
	1,
	{
		(void*)demo_enclave_ocall_print,
	}
};
sgx_status_t ecall_init_ra(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_demo_enclave, NULL);
	return status;
}

sgx_status_t ecall_close_ra(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_demo_enclave, NULL);
	return status;
}

sgx_status_t ecall_verify_att_result_mac(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_demo_enclave, NULL);
	return status;
}

sgx_status_t ecall_put_secrets(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_demo_enclave, NULL);
	return status;
}

sgx_status_t ecall_create_sealed_policy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_demo_enclave, NULL);
	return status;
}

sgx_status_t ecall_perform_sealed_policy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 5, &ocall_table_demo_enclave, NULL);
	return status;
}

sgx_status_t ecall_start_heartbeat(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 6, &ocall_table_demo_enclave, NULL);
	return status;
}

sgx_status_t ecall_perform_fun_1(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 7, &ocall_table_demo_enclave, NULL);
	return status;
}

sgx_status_t ecall_perform_fun_2(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 8, &ocall_table_demo_enclave, NULL);
	return status;
}

