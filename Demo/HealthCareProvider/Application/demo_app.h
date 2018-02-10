#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
# include <unistd.h>
# include <pwd.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_urts.h"

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "demo_enclave.token"
# define ENCLAVE_FILENAME "demo_enclave.signed.so"

# define MAX_PATH FILENAME_MAX

extern sgx_enclave_id_t global_eid;
