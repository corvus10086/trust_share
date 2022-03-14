#include <sgx_error.h>
#include <string.h>
#include "libc_proxy.h"
#include "file_mock.h"
#define TRACE_LIBC_CALLS

/* STDIO */
FILE *const stdin  = (FILE*)0;
FILE *const stdout = (FILE*)1;
FILE *const stderr = (FILE*)2;

FILE *fopen(const char *path, const char *mode) {
    FILE *ret = fmock_open(path);
#ifdef TRACE_LIBC_CALLS
    if( ret == NULL )
    printf("FILE *fopen(const char *path='%s', const char *mode='%s')\n", path, mode);
#endif
    return ret;
}

FILE *freopen(const char *path, const char *mode, FILE *stream) {
#ifdef TRACE_LIBC_CALLS
    printf("FILE *freopen(const char *path='%s', const char *mode='%s', FILE *stream)\n", path, mode);
#endif
}

int fclose(FILE *f) {
    return fmock_close(f);
}

int remove(const char *pathname) {
#ifdef TRACE_LIBC_CALLS
    printf("remove(const char *pathname='%s')\n",pathname);
#endif
}

int rename(const char *oldpath, const char *newpath) {
#ifdef TRACE_LIBC_CALLS
    printf("int rename(const char *oldpath='%s', const char *newpath='%s')\n", oldpath, newpath);
#endif
}

int feof(FILE *f) {
    return fmock_feof(f);
}

int ferror(FILE *f) {
    return 0;
}

int fflush(FILE *f) {
    return 0;
}

void clearerr(FILE *f) {
#ifdef TRACE_LIBC_CALLS
    printf("void clearerr(FILE *f)\n");
#endif
}

int fseek(FILE *f, long offset, int whence) {
#ifdef TRACE_LIBC_CALLS
    printf("int fseek(FILE *f, long offset, int whence)\n");
#endif
}

long ftell(FILE *f) {
#ifdef TRACE_LIBC_CALLS
    printf("long ftell(FILE *f)\n");
#endif
}

int getc(FILE *f) {
    int ret = fmock_getc(f);
#ifdef TRACE_LIBC_CALLS
    if( ret == EOF )
    printf("int getc(FILE *f)\n");
#endif
    return ret;
}

int ungetc(int c, FILE *f) {
#ifdef TRACE_LIBC_CALLS
    printf("int ungetc(int c, FILE *f)\n");
#endif
}

char *fgets(char *s, int size, FILE *stream) {
#ifdef TRACE_LIBC_CALLS
    printf("char *fgets(char *s, int size, FILE *stream)\n");
#endif
    return NULL;
}

int fputc(int c, FILE *stream) {
    unsigned char out = c;
    if( fwrite( &out, 1, sizeof(out), stream ) )
        return c;
    else {
#ifdef TRACE_LIBC_CALLS
        printf("int fputc(int c='%c', FILE *stream='%ld')\n", c, (long int)stream);
#endif
        return EOF;
    }
}

//------------------------------------------------------------------------------
#include <stdarg.h>
#define stdfile_str(a) (a == stdout ? "stdout" : "\033[31mstderr\033[0m")
#define outerr_str(a,b) (printf("%s: %s", stdfile_str(a), (const char*)b))
//------------------------------------------------------------------------------
int fprintf(FILE *stream, const char *format, ...) {
    char buf[1024] = {'\0'};
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf,sizeof(buf),format,ap);
    va_end(ap);
    return fwrite(buf,1,strlen(buf),stream);
}

//------------------------------------------------------------------------------
int __fprintf_chk(FILE *stream, int flag, const char *format, ...) {
    (void)flag;
    int ret;
    va_list ap;
    va_start(ap, format);
    ret = fprintf(stream,format,ap);
    va_end(ap);
    return ret;
}

//------------------------------------------------------------------------------
int __printf_chk(int flag, const char *format, ...) {
    (void)flag;
    int ret;
    va_list ap;
    va_start(ap, format);
    ret = printf(format,ap);
    va_end(ap);
    return ret;
}


//------------------------------------------------------------------------------
int vfprintf (FILE *f, const char *format, va_list v) {
    char buf[1024] = {'\0'};
    vsnprintf(buf,sizeof(buf),format,v);
    int ret = fwrite(buf,1,strlen(buf),f);
    return ret;
}

//------------------------------------------------------------------------------
int snprintf( char *str, size_t sz, const char *fmt, ... ) {
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = vsnprintf(str,sz,fmt,ap);
    va_end(ap);
    return ret;
}

//------------------------------------------------------------------------------
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t ret = fmock_fread(ptr,size,nmemb,stream);
#ifdef TRACE_LIBC_CALLS
    if( !ret )
    printf("size_t fread(void *ptr, size_t size='%d', size_t nmemb='%d', FILE *stream='%ld')\n",size, nmemb, (long int)stream);
#endif
    return ret;
}

//------------------------------------------------------------------------------
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t ret = 0;
    if(stream == stdout || stream == stderr) {
        ret = outerr_str(stream,ptr) / size;
    } else {
        ret = fmock_fwrite(ptr,size,nmemb,stream);
#ifdef TRACE_LIBC_CALLS
        if(!ret) printf("size_t fwrite(const void *ptr, size_t size='%d', size_t nmemb='%d', FILE *stream='%ld') : %d\n",size, nmemb, (long int)stream, ret);
#endif
    }
    return ret;
}

//------------------------------------------------------------------------------
int setvbuf(FILE *stream, char *buf, int mode, size_t size) {
#ifdef TRACE_LIBC_CALLS
    printf("int setvbuf(FILE *stream, char *buf, int mode, size_t size)\n");
#endif
}

char *tmpnam(char *s) {
#ifdef TRACE_LIBC_CALLS
    printf("char *tmpnam(char *s)\n");
#endif
}

FILE *tmpfile(void) {
#ifdef TRACE_LIBC_CALLS
    printf("FILE *tmpfile(void)\n");
#endif
}

/* STDLIB */
int rand (void) {
    int ret = -1;
    unsigned long rnd;
    if( sgx_read_rand( &rnd, sizeof(unsigned long) ) == SGX_SUCCESS )
        ret = rnd % RAND_MAX;
#if defined TRACE_LIBC_CALLS && defined TRACE_STDLIB
    printf("int rand (void) = %d\n", ret);
#endif
    return ret;
}

void srand (unsigned seed) {
#ifdef TRACE_LIBC_CALLS
    printf("void srand (unsigned seed)\n");
#endif
}

char *getenv (const char *name) {
    return NULL;
}

int system (const char *command) {
#ifdef TRACE_LIBC_CALLS
    printf("int system (const char *command)\n");
#endif
}

void exit (int status) {
#ifdef TRACE_LIBC_CALLS
    printf("void exit (int status='%d')\n",status);
#endif
}

/* STRING */
char *strcpy (char *dest, const char *src) { strncpy(dest,src,strlen(src)+1); }

/* TIME */
time_t mktime (struct tm *t) {
#ifdef TRACE_LIBC_CALLS
    printf("time_t mktime (struct tm *t)\n");
#endif
}

struct tm *gmtime (const time_t *timep) {
#ifdef TRACE_LIBC_CALLS
    printf("struct tm *gmtime (const time_t *timep)\n");
#endif
}

struct tm *localtime (const time_t *timep) {
#ifdef TRACE_LIBC_CALLS
    printf("struct tm *localtime (const time_t *timep)\n");
#endif
}

#ifdef DUMMY_TIME
time_t time (time_t *__timer) {
#ifdef TRACE_LIBC_CALLS
    printf("time_t time (time_t *__timer)\n");
#endif
    return 0;
}
#endif

clock_t clock (void) {
#ifdef TRACE_LIBC_CALLS
    printf("clock_t clock (void)\n");
#endif
}

/* LOCALE */
char *setlocale (int category, const char *locale) {
#ifdef TRACE_LIBC_CALLS
    printf("char *setlocale (int category, const char *locale)\n");
#endif
}

struct lconv *localeconv(void) {
    static struct lconv l;
    l.decimal_point =
    l.mon_decimal_point = ".";
    l.thousands_sep = 
    l.grouping = 
    l.int_curr_symbol = 
    l.currency_symbol = 
    l.mon_thousands_sep = 
    l.mon_grouping = 
    l.positive_sign = 
    l.negative_sign= "";

    l.int_frac_digits =
    l.frac_digits =
    l.p_cs_precedes =
    l.p_sep_by_space =
    l.n_cs_precedes =
    l.n_sep_by_space =
    l.p_sign_posn =
    l.n_sign_posn =
    l.int_p_cs_precedes =
    l.int_p_sep_by_space =
    l.int_n_cs_precedes =
    l.int_n_sep_by_space =
    l.int_p_sign_posn =
    l.int_n_sign_posn = 127; 

    return &l;
}

int raise(int sig) {
#ifdef TRACE_LIBC_CALLS
    printf("raise(sig=%d)\n",sig);
#endif
    return 0;
}

