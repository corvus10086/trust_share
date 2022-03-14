#include <sgx_utils_rp.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <libgen.h>
#include <mutex>
//------------------------------------------------------------------------------
// Change dir to that ot the file f
//------------------------------------------------------------------------------
void change_dir( char *f ) {
    char *ptr = NULL;
    ptr = realpath( dirname(f),NULL );
    if( ptr == NULL ){ perror("Error:"); abort(); }
    if( chdir(ptr) != 0) abort();
}

//------------------------------------------------------------------------------
void exit_error( int exit_code, const char *fmt, ... ) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf( stderr, fmt, ap );
    va_end( ap );
    fflush(stderr);
    exit( exit_code );
}

//------------------------------------------------------------------------------
int set_rand_seed() {
    FILE *f = fopen("/dev/urandom", "r");
    if( f == NULL ) return -1;
    unsigned seed;
    size_t ret = fread( &seed, sizeof(seed), 1, f );
    fclose(f);
    srand(seed);

    if( ret == sizeof(seed) )
        return 0;
    else
        return 1;
}

//------------------------------------------------------------------------------
static uint8_t s_logmask_ = 0;
static std::mutex s_lmask_mtx;
void set_logmask( uint8_t l ) {
    std::lock_guard<std::mutex> lk(s_lmask_mtx);
    s_logmask_ = l;
}

//------------------------------------------------------------------------------
void printinfo( uint8_t level, const char *format , ... ) {
    uint8_t mask;
    {
        std::lock_guard<std::mutex> lk(s_lmask_mtx);
        mask = s_logmask_;
    }

    FILE *file = level & LLCRIT ? stderr : stdout;
    if( level & mask ) {
        va_list arglist;
        va_start( arglist, format );
        vfprintf( file, format, arglist );
        va_end( arglist );
    }
}

//------------------------------------------------------------------------------

