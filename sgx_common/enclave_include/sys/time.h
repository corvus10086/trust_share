#ifndef _MOCK_TIME_H_
#define _MOCK_TIME_H_

#include <stdlib.h>
#include <time.h>

typedef long int __suseconds_t;
typedef __suseconds_t suseconds_t;

struct timeval
{
    __time_t tv_sec;        /* Seconds.  */
    __suseconds_t tv_usec;  /* Microseconds.  */
};

#endif

