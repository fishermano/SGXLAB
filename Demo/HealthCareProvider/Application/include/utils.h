#include <stdio.h>

// Needed for definition of remote attestation messages.
#include "remote_attestation_msg.h"

void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len);

void PRINT_ATTESTATION_SERVICE_RESPONSE(FILE *file, ra_samp_response_header_t *response);
