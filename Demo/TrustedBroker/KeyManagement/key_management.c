#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include "key_management.h"
#include "remote_attestation_result.h"

#define SAMPLE_SP_IV_SIZE        12

extern sample_aes_gcm_128bit_key_t secret_share_key;
extern sample_aes_gcm_128bit_key_t d_key1;
extern sample_aes_gcm_128bit_key_t d_key2;
extern sample_aes_gcm_128bit_key_t d_key3;
extern sample_aes_gcm_128bit_key_t d_key4;

int cert_check(){
  return 0;
}

int key_retrieve(uint8_t hcp_id, sp_samp_key_set_t **pp_key_set){

  sp_samp_key_set_t *key_set = NULL;
  uint8_t key_num = 4;

  uint32_t key_size = key_num * sizeof(sample_aes_gcm_128bit_key_t);
  key_set = (sp_samp_key_set_t *)malloc(sizeof(sp_samp_key_set_t) + key_size);
  if(NULL == key_set){
    fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
    return -1;
  }
  memset(key_set, 0, sizeof(sp_samp_key_set_t) + key_size);

  key_set->key_num = key_num;
  memcpy(key_set->keys[0], d_key1, sizeof(d_key1));
  memcpy(key_set->keys[1], d_key2, sizeof(d_key2));
  memcpy(key_set->keys[2], d_key3, sizeof(d_key3));
  memcpy(key_set->keys[3], d_key4, sizeof(d_key4));

  *pp_key_set = key_set;

  return 0;
}

int sp_km_proc_key_req(const hcp_samp_certificate_t *p_cert, kd_samp_package_header_t **response){

  kd_samp_package_header_t *p_resp = NULL;
  sp_aes_gcm_data_t *p_encrypted_keys = NULL;
  sp_samp_key_set_t *p_key_set = NULL;


  /*
    check p_cert to judge whether it is a legal health care provider
  */

  if(0 != cert_check()){
    return -1;
  }

  /*
    deliver granted device keys to demo_app
  */
  uint8_t hcp_id = 1;
  if(0 != key_retrieve(hcp_id, &p_key_set)){
    return -1;
  }

  fprintf(stdout, "\nkey number: %d \n", p_key_set->key_num);
  for(uint8_t i =0; i<p_key_set->key_num; i++){
    for(uint8_t j = 0; j<16; j++){
      fprintf(stdout, "key %d: %d\n", i, p_key_set->keys[i][j]);
    }
    fprintf(stdout, "*********************\n\n");
  }

  uint32_t key_set_size = (p_key_set->key_num * sizeof(sample_aes_gcm_128bit_key_t)) + sizeof(sp_samp_key_set_t);

  uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};
  p_encrypted_keys = (sp_aes_gcm_data_t *)malloc(sizeof(sp_aes_gcm_data_t) + key_set_size);
  memset(p_encrypted_keys, 0, sizeof(sp_aes_gcm_data_t) + key_set_size);
  if(!p_encrypted_keys){
    fprintf(stderr, "\nError, out of memory in [%s].\n", __FUNCTION__);
    return -1;
  }
  int ret = sample_rijndael128GCM_encrypt(&secret_share_key,
              &p_key_set->key_num,
              key_set_size,
              p_encrypted_keys->payload,
              &aes_gcm_iv[0],
              SAMPLE_SP_IV_SIZE,
              NULL,
              0,
              &p_encrypted_keys->payload_tag);
  if(SAMPLE_SUCCESS != ret){
    fprintf(stderr, "\nError, data encryption in [%s].\n", __FUNCTION__);
    return -1;
  }

  p_encrypted_keys->payload_size = key_set_size;

  p_resp = (kd_samp_package_header_t *)malloc(sizeof(kd_samp_package_header_t) + sizeof(sp_aes_gcm_data_t) + key_set_size);
  if(!p_resp){
    fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
    return -1;
  }
  memset(p_resp, 0, sizeof(kd_samp_package_header_t) + sizeof(sp_aes_gcm_data_t) + key_set_size);

  p_resp->type = TYPE_KEY_RESPONSE;
  p_resp->size = sizeof(sp_aes_gcm_data_t) + key_set_size;

  memcpy(p_resp->body, p_encrypted_keys, sizeof(sp_aes_gcm_data_t) + key_set_size);

  *response = p_resp;

  return 0;
}
