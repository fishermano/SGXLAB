#include "App.h"

sgx_enclave_id_t global_eid = 0;

#define DATA_SIZE 1

typedef struct _file_t {
  uint8_t payload_size;
  uint8_t payload_tag[16];
  uint8_t payload[DATA_SIZE];
} enc_file;

void write_result(const char *res_file, int file_num, double dec_time){
  FILE *out = fopen(res_file, "a");
  if (out == NULL){
    printf("cannot open file %s\n", res_file);
    return;
  }
  fprintf(out, "%d,%lf\n", file_num, dec_time);
  fclose(out);
  return;
}

/* Check error conditions for loading enclave */
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

void ocall_print(const char* str){
  printf("%s\n", str);
}

void ocall_print_int(int num){
  printf("The number is: %d\n", num);
}

int SGX_CDECL main(int argc, char *argv[]){
  (void)(argc);
  (void)(argv);

  sgx_status_t ret = SGX_SUCCESS;
  sgx_status_t status = OPERATION_SUC;

  if(initialize_enclave() < 0){
    printf("Enter a character before exit ... \n");
    getchar();
    return -1;
  }

  // ret = ecall_decrypt(global_eid);

  uint8_t ssk[16] = {
    0x72, 0xee, 0x30, 0xb0,
    0x1d, 0xd9, 0x11, 0x38,
    0x24, 0x11, 0x14, 0x3a,
    0xe2, 0xaa, 0x60, 0x38
  };

  // uint8_t evaluation_data[8] = {
  //   0xf5, 0x5b, 0x56, 0xf0, 0xac, 0x7f, 0x78, 0x39
  // };

  uint8_t evaluation_data[1] = {
    0xf5
  };
  size_t length = DATA_SIZE;

  uint8_t evaluation_data_output[DATA_SIZE] = {0};

  size_t tag_len = 16;
  size_t add_len = 0;
	uint8_t *add = NULL;
	size_t iv_len = 12;
	uint8_t iv[12] = {0};

  #define FILE_NUM 1000
  #define START_FILE_NUM 10
  #define FILE_NUM_STEP 10
  #define BASELINE_RESULT_FILE "./baseline_results/baseline_results_1bytes.txt"
  #define RESULT_FILE "./results/results_1bytes.txt"

  enc_file eval_files[FILE_NUM] = {0};

  printf("\nStarting encrypting data\n");
  for(int q = 0; q < FILE_NUM; q++){
    encryption(ssk,
      iv, iv_len,
      add, add_len,
      evaluation_data, length,
      eval_files[q].payload,
      eval_files[q].payload_tag, tag_len);
    eval_files[q].payload_size = DATA_SIZE;
    printf("\nFile %d encrypted!!!\n", (q + 1));
  }


  clock_t start, end;
  double exe_time;
  int v;

  printf("\nStarting baseline decrypting data\n");
  for(v = START_FILE_NUM; v <= FILE_NUM; ){
    start = clock();
    for(int b = 0; b < v; b++){
      ret = decryption(ssk,
        iv, iv_len,
        add, add_len,
        eval_files[b].payload_tag, tag_len,
        eval_files[b].payload, eval_files[b].payload_size,
        evaluation_data_output);
      if(OPERATION_SUC != ret){
        fprintf(stderr, "\nError, evaluation decryption using shared key based AESGCM failed in [%s]. ret = 0x%0x.", __FUNCTION__, ret);
      }
    }
    end = clock();
    exe_time = (double)(end - start)/CLOCKS_PER_SEC;

    printf("\nwriting to baseline result file: %d \n", v);
    write_result(BASELINE_RESULT_FILE, v, exe_time);
    v = v + FILE_NUM_STEP;
  }


  for(v = START_FILE_NUM; v <= FILE_NUM; ){
    start = clock();
    ret = ecall_evaluate_decryption(global_eid, &status, &eval_files[0].payload_size, v, v*(DATA_SIZE + 17));
    end = clock();
    exe_time = (double)(end - start)/CLOCKS_PER_SEC;
    // printf("\nfile numbers: %d; time: %lf\n", FILE_NUM, exe_time);
    printf("\nwriting to result file: %d\n", v);
    write_result(RESULT_FILE, v, exe_time);
    v = v + FILE_NUM_STEP;

    if((SGX_SUCCESS != ret) || (OPERATION_SUC != status)){
      fprintf(stderr, "\nError, evaluation decryption using shared key based AESGCM failed in [%s]. ret = 0x%0x. status = 0x%0x", __FUNCTION__, ret, status);
    }
  }


  sgx_destroy_enclave(global_eid);

  printf("Info: Enclave Successfully Retrurned. \n");

  printf("Enter a character before exit ... \n");
  getchar();
  return 0;

}
