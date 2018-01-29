#include <stdio.h>
#include <string.h>

#include "openssl_aes.h"
#include "read_dir.h"

#define MAX_NAME_LEN 100

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
  strcpy(base_path, "./plaintexts/");
  struct file_list fl = read_dir(base_path);
  for(int i = 0; i < fl.file_num; i++){

    char path[MAX_NAME_LEN];
    memset(path, '\0', sizeof(path));
    strcpy(path, "./plaintexts/");
    strcat(path, fl.files[i]);
    printf("reading file %s.....\n", path);

    char *input = get_file_text(path);
    printf("plaintext length is %d\n", (int)strlen(input));

    int olen, len;
    olen = len = strlen(input) + 1;
    unsigned char *ciphertext = aes_encrypt(&en, (unsigned char *)input, &len);
    printf("ciphertext length is %d\n", (int)strlen(ciphertext));

    char *plaintext = (char *)aes_decrypt(&de, ciphertext, &len);

    if (strncmp(plaintext, input, olen))
      printf("FAIL: enc/dec failed for \"%s\"\n", input);
    else
      printf("OK: enc/dec ok for \"%s\"\n", plaintext);

    free(ciphertext);
    free(plaintext);
    free(input);
  }

  EVP_CIPHER_CTX_cleanup(&en);
  EVP_CIPHER_CTX_cleanup(&de);

  return 0;
}
