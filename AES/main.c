#include <stdio.h>
#include <string.h>
#include <time.h>

#include "openssl_aes.h"
#include "file_utils.h"

#define MAX_NAME_LEN 100
#define CUR_DIR "./plaintexts/"
#define RESULT_FILE "./results/1.txt"

int main(int argc, char **argv){
  /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
     status of enc/dec operations */
  EVP_CIPHER_CTX en, de;

  /* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte
     integers on the stack as 64 bits of contigous salt material -
     ofcourse this only works if sizeof(int) >= 4 */
  unsigned int salt[] = {12345, 54321};
  unsigned char *key_material;
  int key_material_len, i;
  int nrounds = 5;

  if (argc == 1){
    printf("one more argv parameter needed!\n");
    printf("use command: ./main [key_material]\n");
    return -1;
  }
  /* the key_data is read from the argument list */
  key_material = (unsigned char *)argv[1];
  key_material_len = strlen(argv[1]);

  /* gen key and iv. init the cipher ctx object */
  if (aes_init(key_material, key_material_len, (unsigned char *)&salt, nrounds, &en, &de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }

  /* read files from a directory, then encrypt and decrypt. */
  char base_path[MAX_NAME_LEN];
  memset(base_path, '\0', sizeof(base_path));
  strcpy(base_path, CUR_DIR);
  struct file_list fl = read_dir(base_path);
  int file_num = fl.file_num;
  char files[file_num][MAX_NAME_LEN];
  for(int k=0; k < file_num; k++){
    memset(files[k], '\0', sizeof(files[k]));
    strcpy(files[k], fl.files[k]);
  }

  char path[MAX_NAME_LEN];
  char *input;
  int olen, len;
  unsigned char *ciphertext;
  char *plaintext;

  clock_t start_enc, end_enc, start_dec, end_dec;
  double enc_time, dec_time;

  for(int i = 0; i < file_num; i++){

    memset(path, '\0', sizeof(path));
    strcpy(path, CUR_DIR);
    strcat(path, files[i]);
    printf("reading file %s.....\n", path);

    input = get_file_text(path);

    olen = len = strlen(input) + 1;

    start_enc = clock();
    ciphertext = aes_encrypt(&en, (unsigned char *)input, &len);
    end_enc = clock();
    enc_time = (double)(end_enc - start_enc)/CLOCKS_PER_SEC;

    start_dec = clock();
    plaintext = (char *)aes_decrypt(&de, ciphertext, &len);
    end_dec = clock();
    dec_time = (double)(end_dec - start_dec)/CLOCKS_PER_SEC;

    if (strncmp(plaintext, input, olen)){
      printf("FAIL: enc/dec failed\n");
    }else{
      printf("**************OK: enc/dec ok*******************\n");
      printf("plaintext length: %d bytes\nciphertext length: %d bytes\nencryption_time: %lf seconds\ndecryption_time: %lf seconds\n", (int)strlen(input), (int)strlen(ciphertext), enc_time, dec_time);
      printf("!!!writing to result file\n!!!");
      write_result(RESULT_FILE, (int)strlen(input), (int)strlen(ciphertext), enc_time, dec_time, 0.0);
    }

    free(ciphertext);
    free(plaintext);
    free(input);
  }

  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);

  return 0;
}
