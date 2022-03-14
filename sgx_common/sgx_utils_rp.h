#include <stdint.h>

#define LLNONE  0
#define LLCRIT  1
#define LLWARN  2
#define LLINFO  4
#define LLLOG   8
#define LLDEBG 16

void set_logmask( uint8_t l );
void printinfo( uint8_t level, const char *format , ... );

void change_dir( char *file );
void exit_error( int exit_code, const char *fmt, ... );
int set_rand_seed(); 

