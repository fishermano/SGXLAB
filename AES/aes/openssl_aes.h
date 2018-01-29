/**
 * AES encryption/decryption demo using OpenSSL EVP APIs
**/

#include <openssl/evp.h>

/**
 * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * A SHA1 digest is used to hash the supplied key material. nrounds is the number of times that we hash the material. More rounds are more secure but slower
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
 int aes_init(unsigned char *key_material, int key_material_len, unsigned char *salt, int nrounds, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);

 /*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
 unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);

 /*
 * Decrypt *len bytes of ciphertext
 */
 unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);
