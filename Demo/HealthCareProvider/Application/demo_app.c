/*
  Needed for defining integer range, eg. INT_MAX
*/
#include <limits.h>

/*
  Needed for untrusted enclave ocall interface
*/
#include "demo_enclave_u.h"

/*
  Needed for some data structures
*/
#include "demo_app.h"

/*
  Needed to perform some utility functions
*/
#include "utils.h"

/*
  Needed to create enclave and do ecall
*/
#include "sgx_urts.h"

/*
  Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
*/
#include "sgx_ukey_exchange.h"

/*
  Needed to query extended epid group id.
*/
#include "sgx_uae_service.h"

/*
  define the enclave id
*/
static sgx_enclave_id_t global_eid = 0;

/*
  print error message for loading enclave
*/
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;

    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/*
  define the untrusted enclave ocall functions
*/
void ocall_print(const char* str){
  printf("%s\n", str);
}

/*
  entry of the application
*/
int SGX_CDECL main(int argc, char *argv[]){

  /*
    define result status of ecall function
  */
  int ret = 0;
  sgx_status_t status = SGX_SUCCESS;

  /*
    define msg0 - msg3 and the attestation result message
  */
  ra_samp_request_header_t *p_msg0_full = NULL;
  ra_samp_response_header_t *p_msg0_resp_full = NULL;
  ra_samp_request_header_t *p_msg1_full = NULL;
  ra_samp_response_header_t *p_msg2_full = NULL;
  ra_samp_request_header_t *p_msg3_full = NULL;
  sgx_ra_msg3_t *p_msg3 = NULL;
  ra_samp_response_header_t *p_att_result_msg_full = NULL;

  /*
    define retry parameters
  */
  int enclave_lost_retry_time = 1;
  int busy_retry_time = 4;

  /*
    define remote attestation context
  */
  sgx_ra_context_t context = INT_MAX;

  /*
    define verification parameters
  */
  int32_t verify_index = -1;
  int32_t verification_samples = sizeof(msg1_samples)/sizeof(msg1_samples[0]);
  #define VERIFICATION_INDEX_IS_VALID() (verify_index > 0 && verify_index <= verification_samples)
  #define GET_VERIFICATION_ARRAY_INDEX() (verify_index-1)

  /*
    define the output source file
  */
  FILE *OUTPUT = stdout;

  if(argc > 1){
    verify_index = atoi(argv[1]);
    if(VERIFICATION_INDEX_IS_VALID()){
      fprintf(OUTPUT, "\nVerifying precomputed attestation messages using precomputed values# %d\n", verify_index);
    }else{
      fprintf(OUTPUT, "\nValid invocations are:\n");
      fprintf(OUTPUT, "\n\t./demo_app\n");
      fprintf(OUTPUT, "\n\t./demo_app <verification index>\n");
      fprintf(OUTPUT, "\nValid indices are [1 - %d]\n",
              verification_samples);
      fprintf(OUTPUT, "\nUsing a verification index uses precomputed messages to assist debugging the remote attestation trusted broker.\n");
      return -1;
    }
  }

  /*
    preparation for remote attestation by configuring extended epid group id - msg0.
  */

  {
    uint32_t extended_epid_group_id = 0;
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if(SGX_SUCCESS != ret){
      ret = -1;
      fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].", __FUNCTION__);
      return ret;
    }
    fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.");

    p_msg0_full = (ra_samp_request_header_t*) malloc(sizeof(ra_samp_request_header_t) + sizeof(uint32_t));

    if(NULL == p_msg0_full){
      ret = -1;
      goto CLEANUP;
    }
    p_msg0_full->type = TYPE_RA_MSG0;
    p_msg0_full->size = sizeof(uint32_t);

    *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;
    {

      fprintf(OUTPUT, "\nMSG0 body generated -\n");

      PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

    }

    fprintf(OUTPUT, "\nSending msg0 to remote attestation trusted broker.\n");

    ret = ra_network_send_receive("http://DemoTesting.vt.edu",
        p_msg0_full,
        &p_msg0_resp_full);
    if (ret != 0)
    {
        fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
            "[%s].", __FUNCTION__);
        goto CLEANUP;
    }
    fprintf(OUTPUT, "\nSent MSG0 to remote attestation service.\n");
  }

  /*
    Remote attestation will be initiated the trusted broker challengs the demo_app of if the demo_app detects it doesn't have the credentials (shared secrets) from a previous attestation required for secure communication with the trusted broker
  */

  {

    do{
      /*
        demo_app initializes its enclave
       */
      if(initialize_enclave() < 0){
        ret = -1;
        fprintf(OUTPUT, "\nError, enclave initialization Failed [%s].",
                __FUNCTION__);
        goto CLEANUP;
      }

      fprintf(OUTPUT, "\nEncalve initialization success.\n");

      ret = ecall_init_ra(global_eid, &status, false, &context);

    }while(SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);
  }

  printf("***Remote Attestation Functionality***\n");
  ecall_verify_att_result_mac(global_eid);
  ecall_put_secrets(global_eid);

  printf("\n***Sealing Secrets Functionality***\n");
  ecall_create_sealed_policy(global_eid);
  ecall_perform_sealed_policy(global_eid);

  printf("\n***Heartbeat Functionality***\n");
  ecall_start_heartbeat(global_eid);

  printf("\n***Functions Functionality***\n");
  ecall_perform_fun_1(global_eid);
  ecall_perform_fun_2(global_eid);

CLEANUP:

  sgx_destroy_enclave(global_eid);

  printf("\n\nInfo: Enclave Successfully Retrurned. \n");

  printf("Enter a character before exit ... \n");
  getchar();
  return ret;

}
