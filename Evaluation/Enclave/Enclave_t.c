#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_ecall_decrypt(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_decrypt();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_evaluate_decryption(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_evaluate_decryption_t));
	ms_ecall_evaluate_decryption_t* ms = SGX_CAST(ms_ecall_evaluate_decryption_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_files = ms->ms_p_files;
	uint32_t _tmp_total_size = ms->ms_total_size;
	size_t _len_p_files = _tmp_total_size;
	uint8_t* _in_p_files = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_files, _len_p_files);

	if (_tmp_p_files != NULL && _len_p_files != 0) {
		_in_p_files = (uint8_t*)malloc(_len_p_files);
		if (_in_p_files == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_files, _tmp_p_files, _len_p_files);
	}
	ms->ms_retval = ecall_evaluate_decryption(_in_p_files, ms->ms_file_number, _tmp_total_size);
err:
	if (_in_p_files) free(_in_p_files);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_decrypt, 0},
		{(void*)(uintptr_t)sgx_ecall_evaluate_decryption, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][2];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, },
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_int(int num)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_print_int_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_int_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_int_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_int_t));

	ms->ms_num = num;
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

