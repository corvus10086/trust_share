#include <libc_mock/libc_proxy.h>
#include <stdio.h>

int _TLIBC_CDECL_ fputs(const char *s, FILE *f) {
    return 0;
}

int _TLIBC_CDECL_ putc(int c, FILE *f) {
    return 0;
}

int _TLIBC_CDECL_ sprintf(char *d, const char *s, ...) {
    return 0;
}

