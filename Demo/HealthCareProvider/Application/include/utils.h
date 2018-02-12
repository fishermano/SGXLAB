#include <stdio.h>

// Needed for definition of remote attestation messages.
#include "network_ra.h"

/*
  for printing some data in memory
*/
void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len);

void PRINT_ATTESTATION_SERVICE_RESPONSE(FILE *file, ra_samp_response_header_t *response);

/*
  interface for communication between demp_app and trusted borker
*/
int ra_network_send_receive(const char *server_url, const ra_samp_request_header_t *p_req, ra_samp_response_header_t **p_resp);
