#include "demo_enclave_t.h"

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


typedef struct ms_ecall_init_ra_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_p_context;
} ms_ecall_init_ra_t;

typedef struct ms_ecall_close_ra_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
} ms_ecall_close_ra_t;

typedef struct ms_ecall_verify_result_mac_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_mac;
	size_t ms_mac_size;
} ms_ecall_verify_result_mac_t;

typedef struct ms_ecall_put_secrets_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
} ms_ecall_put_secrets_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_ecall_create_sealed_policy_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_ecall_create_sealed_policy_t;

typedef struct ms_ecall_perform_sealed_policy_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_log;
	uint32_t ms_sealed_log_size;
} ms_ecall_perform_sealed_policy_t;

typedef struct ms_ecall_put_keys_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_secret;
	uint32_t ms_secret_size;
	uint8_t* ms_gcm_mac;
} ms_ecall_put_keys_t;

typedef struct ms_ecall_heartbeat_process_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_hb;
	uint32_t ms_hb_size;
	uint8_t* ms_gcm_hb_mac;
} ms_ecall_heartbeat_process_t;

typedef struct ms_ecall_perform_statistics_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_secret_1;
	uint32_t ms_secret_size_1;
	uint8_t* ms_gcm_mac_1;
	uint8_t ms_dev_id_1;
	uint8_t* ms_p_secret_2;
	uint32_t ms_secret_size_2;
	uint8_t* ms_gcm_mac_2;
	uint8_t ms_dev_id_2;
	uint32_t* ms_result;
} ms_ecall_perform_statistics_t;

typedef struct ms_ecall_evaluate_decryption_t {
	sgx_status_t ms_retval;
	uint8_t* ms_p_files;
	uint32_t ms_file_number;
	uint32_t ms_total_size;
} ms_ecall_evaluate_decryption_t;

typedef struct ms_ecall_evaluate_encryption_t {
	sgx_status_t ms_retval;
	uint32_t ms_file_number;
} ms_ecall_evaluate_encryption_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_print_int_t {
	int ms_num;
} ms_ocall_print_int_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_init_ra(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_ra_t));
	ms_ecall_init_ra_t* ms = SGX_CAST(ms_ecall_init_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_p_context = ms->ms_p_context;
	size_t _len_p_context = sizeof(*_tmp_p_context);
	sgx_ra_context_t* _in_p_context = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_context, _len_p_context);

	if (_tmp_p_context != NULL && _len_p_context != 0) {
		if ((_in_p_context = (sgx_ra_context_t*)malloc(_len_p_context)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_context, 0, _len_p_context);
	}
	ms->ms_retval = ecall_init_ra(ms->ms_b_pse, _in_p_context);
err:
	if (_in_p_context) {
		memcpy(_tmp_p_context, _in_p_context, _len_p_context);
		free(_in_p_context);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_close_ra(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_close_ra_t));
	ms_ecall_close_ra_t* ms = SGX_CAST(ms_ecall_close_ra_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_close_ra(ms->ms_context);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verify_result_mac(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_result_mac_t));
	ms_ecall_verify_result_mac_t* ms = SGX_CAST(ms_ecall_verify_result_mac_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_message = ms->ms_message;
	size_t _tmp_message_size = ms->ms_message_size;
	size_t _len_message = _tmp_message_size;
	uint8_t* _in_message = NULL;
	uint8_t* _tmp_mac = ms->ms_mac;
	size_t _tmp_mac_size = ms->ms_mac_size;
	size_t _len_mac = _tmp_mac_size;
	uint8_t* _in_mac = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_mac, _len_mac);

	if (_tmp_message != NULL && _len_message != 0) {
		_in_message = (uint8_t*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_message, _tmp_message, _len_message);
	}
	if (_tmp_mac != NULL && _len_mac != 0) {
		_in_mac = (uint8_t*)malloc(_len_mac);
		if (_in_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mac, _tmp_mac, _len_mac);
	}
	ms->ms_retval = ecall_verify_result_mac(ms->ms_context, _in_message, _tmp_message_size, _in_mac, _tmp_mac_size);
err:
	if (_in_message) free(_in_message);
	if (_in_mac) free(_in_mac);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_put_secrets(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_put_secrets_t));
	ms_ecall_put_secrets_t* ms = SGX_CAST(ms_ecall_put_secrets_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_secret = ms->ms_p_secret;
	uint32_t _tmp_secret_size = ms->ms_secret_size;
	size_t _len_p_secret = _tmp_secret_size;
	uint8_t* _in_p_secret = NULL;
	uint8_t* _tmp_gcm_mac = ms->ms_gcm_mac;
	size_t _len_gcm_mac = 16 * sizeof(*_tmp_gcm_mac);
	uint8_t* _in_gcm_mac = NULL;

	if (sizeof(*_tmp_gcm_mac) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_gcm_mac))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_UNIQUE_POINTER(_tmp_p_secret, _len_p_secret);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);

	if (_tmp_p_secret != NULL && _len_p_secret != 0) {
		_in_p_secret = (uint8_t*)malloc(_len_p_secret);
		if (_in_p_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_secret, _tmp_p_secret, _len_p_secret);
	}
	if (_tmp_gcm_mac != NULL && _len_gcm_mac != 0) {
		_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac);
		if (_in_gcm_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_gcm_mac, _tmp_gcm_mac, _len_gcm_mac);
	}
	ms->ms_retval = ecall_put_secrets(ms->ms_context, _in_p_secret, _tmp_secret_size, _in_gcm_mac);
err:
	if (_in_p_secret) free(_in_p_secret);
	if (_in_gcm_mac) free(_in_gcm_mac);

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(*_tmp_g_a);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}
	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
err:
	if (_in_g_a) {
		memcpy(_tmp_g_a, _in_g_a, _len_g_a);
		free(_in_g_a);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(*_tmp_p_msg2);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(*_tmp_p_qe_target);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(*_tmp_p_report);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(*_tmp_p_nonce);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_msg2, _tmp_p_msg2, _len_p_msg2);
	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_qe_target, _tmp_p_qe_target, _len_p_qe_target);
	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}
	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
err:
	if (_in_p_msg2) free((void*)_in_p_msg2);
	if (_in_p_qe_target) free((void*)_in_p_qe_target);
	if (_in_p_report) {
		memcpy(_tmp_p_report, _in_p_report, _len_p_report);
		free(_in_p_report);
	}
	if (_in_p_nonce) {
		memcpy(_tmp_p_nonce, _in_p_nonce, _len_p_nonce);
		free(_in_p_nonce);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(*_tmp_qe_report);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_qe_report, _tmp_qe_report, _len_qe_report);
	}
	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);
err:
	if (_in_qe_report) free(_in_qe_report);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_sealed_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_sealed_policy_t));
	ms_ecall_create_sealed_policy_t* ms = SGX_CAST(ms_ecall_create_sealed_policy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		if ((_in_sealed_log = (uint8_t*)malloc(_len_sealed_log)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_log, 0, _len_sealed_log);
	}
	ms->ms_retval = ecall_create_sealed_policy(_in_sealed_log, _tmp_sealed_log_size);
err:
	if (_in_sealed_log) {
		memcpy(_tmp_sealed_log, _in_sealed_log, _len_sealed_log);
		free(_in_sealed_log);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_perform_sealed_policy(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_perform_sealed_policy_t));
	ms_ecall_perform_sealed_policy_t* ms = SGX_CAST(ms_ecall_perform_sealed_policy_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_log = ms->ms_sealed_log;
	uint32_t _tmp_sealed_log_size = ms->ms_sealed_log_size;
	size_t _len_sealed_log = _tmp_sealed_log_size;
	uint8_t* _in_sealed_log = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_log, _len_sealed_log);

	if (_tmp_sealed_log != NULL && _len_sealed_log != 0) {
		_in_sealed_log = (uint8_t*)malloc(_len_sealed_log);
		if (_in_sealed_log == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_sealed_log, _tmp_sealed_log, _len_sealed_log);
	}
	ms->ms_retval = ecall_perform_sealed_policy((const uint8_t*)_in_sealed_log, _tmp_sealed_log_size);
err:
	if (_in_sealed_log) free((void*)_in_sealed_log);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_put_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_put_keys_t));
	ms_ecall_put_keys_t* ms = SGX_CAST(ms_ecall_put_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_secret = ms->ms_p_secret;
	uint32_t _tmp_secret_size = ms->ms_secret_size;
	size_t _len_p_secret = _tmp_secret_size;
	uint8_t* _in_p_secret = NULL;
	uint8_t* _tmp_gcm_mac = ms->ms_gcm_mac;
	size_t _len_gcm_mac = 16 * sizeof(*_tmp_gcm_mac);
	uint8_t* _in_gcm_mac = NULL;

	if (sizeof(*_tmp_gcm_mac) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_gcm_mac))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_UNIQUE_POINTER(_tmp_p_secret, _len_p_secret);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);

	if (_tmp_p_secret != NULL && _len_p_secret != 0) {
		_in_p_secret = (uint8_t*)malloc(_len_p_secret);
		if (_in_p_secret == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_secret, _tmp_p_secret, _len_p_secret);
	}
	if (_tmp_gcm_mac != NULL && _len_gcm_mac != 0) {
		_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac);
		if (_in_gcm_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_gcm_mac, _tmp_gcm_mac, _len_gcm_mac);
	}
	ms->ms_retval = ecall_put_keys(_in_p_secret, _tmp_secret_size, _in_gcm_mac);
err:
	if (_in_p_secret) free(_in_p_secret);
	if (_in_gcm_mac) free(_in_gcm_mac);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_heartbeat_process(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_heartbeat_process_t));
	ms_ecall_heartbeat_process_t* ms = SGX_CAST(ms_ecall_heartbeat_process_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_hb = ms->ms_p_hb;
	uint32_t _tmp_hb_size = ms->ms_hb_size;
	size_t _len_p_hb = _tmp_hb_size;
	uint8_t* _in_p_hb = NULL;
	uint8_t* _tmp_gcm_hb_mac = ms->ms_gcm_hb_mac;
	size_t _len_gcm_hb_mac = 16 * sizeof(*_tmp_gcm_hb_mac);
	uint8_t* _in_gcm_hb_mac = NULL;

	if (sizeof(*_tmp_gcm_hb_mac) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_gcm_hb_mac))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_UNIQUE_POINTER(_tmp_p_hb, _len_p_hb);
	CHECK_UNIQUE_POINTER(_tmp_gcm_hb_mac, _len_gcm_hb_mac);

	if (_tmp_p_hb != NULL && _len_p_hb != 0) {
		_in_p_hb = (uint8_t*)malloc(_len_p_hb);
		if (_in_p_hb == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_hb, _tmp_p_hb, _len_p_hb);
	}
	if (_tmp_gcm_hb_mac != NULL && _len_gcm_hb_mac != 0) {
		_in_gcm_hb_mac = (uint8_t*)malloc(_len_gcm_hb_mac);
		if (_in_gcm_hb_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_gcm_hb_mac, _tmp_gcm_hb_mac, _len_gcm_hb_mac);
	}
	ms->ms_retval = ecall_heartbeat_process(_in_p_hb, _tmp_hb_size, _in_gcm_hb_mac);
err:
	if (_in_p_hb) free(_in_p_hb);
	if (_in_gcm_hb_mac) free(_in_gcm_hb_mac);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_perform_statistics(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_perform_statistics_t));
	ms_ecall_perform_statistics_t* ms = SGX_CAST(ms_ecall_perform_statistics_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_secret_1 = ms->ms_p_secret_1;
	uint32_t _tmp_secret_size_1 = ms->ms_secret_size_1;
	size_t _len_p_secret_1 = _tmp_secret_size_1;
	uint8_t* _in_p_secret_1 = NULL;
	uint8_t* _tmp_gcm_mac_1 = ms->ms_gcm_mac_1;
	size_t _len_gcm_mac_1 = 16 * sizeof(*_tmp_gcm_mac_1);
	uint8_t* _in_gcm_mac_1 = NULL;
	uint8_t* _tmp_p_secret_2 = ms->ms_p_secret_2;
	uint32_t _tmp_secret_size_2 = ms->ms_secret_size_2;
	size_t _len_p_secret_2 = _tmp_secret_size_2;
	uint8_t* _in_p_secret_2 = NULL;
	uint8_t* _tmp_gcm_mac_2 = ms->ms_gcm_mac_2;
	size_t _len_gcm_mac_2 = 16 * sizeof(*_tmp_gcm_mac_2);
	uint8_t* _in_gcm_mac_2 = NULL;
	uint32_t* _tmp_result = ms->ms_result;
	size_t _len_result = sizeof(*_tmp_result);
	uint32_t* _in_result = NULL;

	if (sizeof(*_tmp_gcm_mac_1) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_gcm_mac_1))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	if (sizeof(*_tmp_gcm_mac_2) != 0 &&
		16 > (SIZE_MAX / sizeof(*_tmp_gcm_mac_2))) {
		status = SGX_ERROR_INVALID_PARAMETER;
		goto err;
	}

	CHECK_UNIQUE_POINTER(_tmp_p_secret_1, _len_p_secret_1);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac_1, _len_gcm_mac_1);
	CHECK_UNIQUE_POINTER(_tmp_p_secret_2, _len_p_secret_2);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac_2, _len_gcm_mac_2);
	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	if (_tmp_p_secret_1 != NULL && _len_p_secret_1 != 0) {
		_in_p_secret_1 = (uint8_t*)malloc(_len_p_secret_1);
		if (_in_p_secret_1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_secret_1, _tmp_p_secret_1, _len_p_secret_1);
	}
	if (_tmp_gcm_mac_1 != NULL && _len_gcm_mac_1 != 0) {
		_in_gcm_mac_1 = (uint8_t*)malloc(_len_gcm_mac_1);
		if (_in_gcm_mac_1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_gcm_mac_1, _tmp_gcm_mac_1, _len_gcm_mac_1);
	}
	if (_tmp_p_secret_2 != NULL && _len_p_secret_2 != 0) {
		_in_p_secret_2 = (uint8_t*)malloc(_len_p_secret_2);
		if (_in_p_secret_2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_p_secret_2, _tmp_p_secret_2, _len_p_secret_2);
	}
	if (_tmp_gcm_mac_2 != NULL && _len_gcm_mac_2 != 0) {
		_in_gcm_mac_2 = (uint8_t*)malloc(_len_gcm_mac_2);
		if (_in_gcm_mac_2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_gcm_mac_2, _tmp_gcm_mac_2, _len_gcm_mac_2);
	}
	if (_tmp_result != NULL && _len_result != 0) {
		if ((_in_result = (uint32_t*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	ms->ms_retval = ecall_perform_statistics(_in_p_secret_1, _tmp_secret_size_1, _in_gcm_mac_1, ms->ms_dev_id_1, _in_p_secret_2, _tmp_secret_size_2, _in_gcm_mac_2, ms->ms_dev_id_2, _in_result);
err:
	if (_in_p_secret_1) free(_in_p_secret_1);
	if (_in_gcm_mac_1) free(_in_gcm_mac_1);
	if (_in_p_secret_2) free(_in_p_secret_2);
	if (_in_gcm_mac_2) free(_in_gcm_mac_2);
	if (_in_result) {
		memcpy(_tmp_result, _in_result, _len_result);
		free(_in_result);
	}

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

static sgx_status_t SGX_CDECL sgx_ecall_evaluate_encryption(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_evaluate_encryption_t));
	ms_ecall_evaluate_encryption_t* ms = SGX_CAST(ms_ecall_evaluate_encryption_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = ecall_evaluate_encryption(ms->ms_file_number);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[14];
} g_ecall_table = {
	14,
	{
		{(void*)(uintptr_t)sgx_ecall_init_ra, 0},
		{(void*)(uintptr_t)sgx_ecall_close_ra, 0},
		{(void*)(uintptr_t)sgx_ecall_verify_result_mac, 0},
		{(void*)(uintptr_t)sgx_ecall_put_secrets, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
		{(void*)(uintptr_t)sgx_ecall_create_sealed_policy, 0},
		{(void*)(uintptr_t)sgx_ecall_perform_sealed_policy, 0},
		{(void*)(uintptr_t)sgx_ecall_put_keys, 0},
		{(void*)(uintptr_t)sgx_ecall_heartbeat_process, 0},
		{(void*)(uintptr_t)sgx_ecall_perform_statistics, 0},
		{(void*)(uintptr_t)sgx_ecall_evaluate_decryption, 0},
		{(void*)(uintptr_t)sgx_ecall_evaluate_encryption, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[11][14];
} g_dyn_entry_table = {
	11,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(*sid);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sid);
		memset(ms->ms_sid, 0, _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		memset(ms->ms_dh_msg1, 0, _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;
	if (sid) memcpy((void*)sid, ms->ms_sid, _len_sid);
	if (dh_msg1) memcpy((void*)dh_msg1, ms->ms_dh_msg1, _len_dh_msg1);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		memcpy(ms->ms_dh_msg2, dh_msg2, _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		memset(ms->ms_dh_msg3, 0, _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, ms->ms_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(4, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		memcpy(ms->ms_pse_message_req, pse_message_req, _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		memset(ms->ms_pse_message_resp, 0, _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(5, ms);

	if (retval) *retval = ms->ms_retval;
	if (pse_message_resp) memcpy((void*)pse_message_resp, ms->ms_pse_message_resp, _len_pse_message_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memset(ms->ms_cpuinfo, 0, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(6, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(7, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

