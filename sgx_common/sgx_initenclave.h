#ifndef _SGX_INITENCLAVE_DEFINED_H_
#define _SGX_INITENCLAVE_DEFINED_H_

#include <sgx_urts.h>
#define MAX_PATH FILENAME_MAX

extern "C" {
int initialize_enclave( sgx_enclave_id_t &global_eid,
                        const char *signed_so_fname,
                        const char *token_fname );
int destroy_enclave(sgx_enclave_id_t eid);
}
#endif

