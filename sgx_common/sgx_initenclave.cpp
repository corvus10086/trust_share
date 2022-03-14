#include <sgx_initenclave.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <sgx_errlist.h>
#include <sgx_utils_rp.h>

//------------------------------------------------------------------------------
/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave( sgx_enclave_id_t &global_eid,
                        const char *signed_so_fname,
                        const char *token_fname ) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+strlen(token_fname)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, token_fname, strlen(token_fname)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, token_fname, strlen(token_fname));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printinfo( LLWARN, "Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printinfo( LLDEBG, "token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printinfo( LLWARN, "Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(signed_so_fname, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if ( !updated || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printinfo( LLWARN, "Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}


//------------------------------------------------------------------------------
int destroy_enclave(sgx_enclave_id_t eid) {
  if( sgx_destroy_enclave(eid) != SGX_SUCCESS ) {
    printinfo( LLCRIT, "App: Error: destroy_enclave() < 0.");
    return -1;
  }
  return 0;
}

