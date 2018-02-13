/*
  Needed for defining integer range, eg. INT_MAX
*/
#include <limits.h>
#include <memory.h>

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

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

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
    fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.\n");

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

    ret = ra_network_send_receive("http://demo_testing.cnsr.vt.edu/", p_msg0_full, &p_msg0_resp_full);
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

    if(SGX_SUCCESS != ret || status)
    {
      ret = -1;
      fprintf(OUTPUT, "\nError, call ecall_init_ra fail [%s].",
              __FUNCTION__);
      goto CLEANUP;
    }
    fprintf(OUTPUT, "\nCall ecall_init_ra success.\n");

  }

  /*
    msg1
  */
  {
    p_msg1_full = (ra_samp_request_header_t*)
                  malloc(sizeof(ra_samp_request_header_t) + sizeof(sgx_ra_msg1_t));
    if(NULL == p_msg1_full){
      ret = -1;
      goto CLEANUP;
    }
    p_msg1_full->type = TYPE_RA_MSG1;
    p_msg1_full->size = sizeof(sgx_ra_msg1_t);

    do{
      ret = sgx_ra_get_msg1(context, global_eid, sgx_ra_get_ga, (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full + sizeof(ra_samp_request_header_t)));
      sleep(3); // Wait 3s between retries
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    if(SGX_SUCCESS != ret)
    {
      ret = -1;
      fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1 fail [%s].",
              __FUNCTION__);
      goto CLEANUP;
    }
    else
    {
      fprintf(OUTPUT, "\nCall sgx_ra_get_msg1 success.\n");

      fprintf(OUTPUT, "\nMSG1 body generated -\n");

      PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
    }

    if(VERIFICATION_INDEX_IS_VALID()){

      // memcpy_s(p_msg1_full->body, p_msg1_full->size, msg1_samples[GET_VERIFICATION_ARRAY_INDEX()], p_msg1_full->size);
      //
      // fprintf(OUTPUT, "\nInstead of using the recently generated MSG1, "
      //                 "we will use the following precomputed MSG1 -\n");
      //
      // PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);

    }


    // The demo_app sends msg1 to the trusted broker to get msg2,
    // msg2 needs to be freed when no longer needed.
    // The demo_app decides whether to use linkable or unlinkable signatures.
    fprintf(OUTPUT, "\nSending msg1 to remote attestation service provider. Expecting msg2 back.\n");

    ret = ra_network_send_receive("http://demo_testing.cnsr.vt.edu/", p_msg1_full, &p_msg2_full);

    if(ret != 0 || !p_msg2_full){
      fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed [%s].", __FUNCTION__);

      if(VERIFICATION_INDEX_IS_VALID()){
        // fprintf(OUTPUT, "\nBecause we are in verification mode we will ignore this error.\n");
        // fprintf(OUTPUT, "\nInstead, we will pretend we received the following MSG2 - \n");
        //
        // SAFE_FREE(p_msg2_full);
        // ra_samp_response_header_t* precomputed_msg2 =
        //     (ra_samp_response_header_t*)msg2_samples[
        //         GET_VERIFICATION_ARRAY_INDEX()];
        // const size_t msg2_full_size = sizeof(ra_samp_response_header_t)
        //                               +  precomputed_msg2->size;
        // p_msg2_full =
        //     (ra_samp_response_header_t*)malloc(msg2_full_size);
        // if(NULL == p_msg2_full)
        // {
        //     ret = -1;
        //     goto CLEANUP;
        // }
        // memcpy_s(p_msg2_full, msg2_full_size, precomputed_msg2,
        //          msg2_full_size);
        //
        // PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
        //                  sizeof(ra_samp_response_header_t)
        //                  + p_msg2_full->size);
      }else{
        goto CLEANUP;
      }
    }else{
      // Successfully sent msg1 and received a msg2 back.
      // Time now to check msg2.
      if(TYPE_RA_MSG2 != p_msg2_full->type){

        fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. [%s].", __FUNCTION__);

        if(VERIFICATION_INDEX_IS_VALID()){
          fprintf(OUTPUT, "\nBecause we are in verification mode we will ignore this error.");
        }
        else{
            goto CLEANUP;
        }
      }

      fprintf(OUTPUT, "\nSent MSG1 to remote attestation trusted broker. Received the following MSG2:\n");
      PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full, sizeof(ra_samp_response_header_t) + p_msg2_full->size);

      fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
      PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

      if( VERIFICATION_INDEX_IS_VALID() )
      {
        // The response should match the precomputed MSG2:
        ra_samp_response_header_t* precomputed_msg2 =
            (ra_samp_response_header_t *)
            msg2_samples[GET_VERIFICATION_ARRAY_INDEX()];
        if(MSG2_BODY_SIZE !=
            sizeof(ra_samp_response_header_t) + p_msg2_full->size ||
            memcmp( precomputed_msg2, p_msg2_full,
                sizeof(ra_samp_response_header_t) + p_msg2_full->size)){

            fprintf(OUTPUT, "\nVerification ERROR. Our precomputed value for MSG2 does NOT match.\n");
            fprintf(OUTPUT, "\nPrecomputed value for MSG2:\n");
            PRINT_BYTE_ARRAY(OUTPUT, precomputed_msg2, sizeof(ra_samp_response_header_t) + precomputed_msg2->size);
            fprintf(OUTPUT, "\nA more descriptive representation of precomputed value for MSG2:\n");
            PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, precomputed_msg2);
        }else{
          fprintf(OUTPUT, "\nVerification COMPLETE. Remote attestation trusted broker generated a matching MSG2.\n");
        }
      }
    }
  }

  /*
    msg3
   */
  {
    sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full + sizeof(ra_samp_response_header_t));

    uint32_t msg3_size = 0;
    if( VERIFICATION_INDEX_IS_VALID())
    {
      // // We cannot generate a valid MSG3 using the precomputed messages
      // // we have been using. We will use the precomputed msg3 instead.
      // msg3_size = MSG3_BODY_SIZE;
      // p_msg3 = (sgx_ra_msg3_t*)malloc(msg3_size);
      // if(NULL == p_msg3)
      // {
      //     ret = -1;
      //     goto CLEANUP;
      // }
      // memcpy_s(p_msg3, msg3_size,
      //          msg3_samples[GET_VERIFICATION_ARRAY_INDEX()], msg3_size);
      // fprintf(OUTPUT, "\nBecause MSG1 was a precomputed value, the MSG3 "
      //                 "we use will also be. PRECOMPUTED MSG3 - \n");
    }else{
      busy_retry_time = 2;
      // The demo_app now calls uKE sgx_ra_proc_msg2,
      // The demo_app is responsible for freeing the returned p_msg3!!
      do
      {
        ret = sgx_ra_proc_msg2(context,
                           global_eid,
                           sgx_ra_proc_msg2_trusted,
                           sgx_ra_get_msg3_trusted,
                           p_msg2_body,
                           p_msg2_full->size,
                           &p_msg3,
                           &msg3_size);
      }while(SGX_ERROR_BUSY == ret && busy_retry_time--);

      if(!p_msg3){
        fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. p_msg3 = 0x%p [%s].", p_msg3, __FUNCTION__);
        ret = -1;
        goto CLEANUP;
      }

      if(SGX_SUCCESS != (sgx_status_t)ret){
        fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. ret = 0x%08x [%s].", ret, __FUNCTION__);
        ret = -1;
        goto CLEANUP;
      }else{
        fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2 success.\n");
        fprintf(OUTPUT, "\nMSG3 - \n");
      }
    }

    PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

    // p_msg3_full = (ra_samp_request_header_t*)malloc(
    //                sizeof(ra_samp_request_header_t) + msg3_size);
    // if(NULL == p_msg3_full)
    // {
    //   ret = -1;
    //   goto CLEANUP;
    // }
    // p_msg3_full->type = TYPE_RA_MSG3;
    // p_msg3_full->size = msg3_size;
    // if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size)){
    //   fprintf(OUTPUT,"\nError: INTERNAL ERROR - memcpy failed in [%s].", __FUNCTION__);
    //   ret = -1;
    //   goto CLEANUP;
    // }

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
