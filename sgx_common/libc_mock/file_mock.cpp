#include "libc_proxy.h"
#include "file_mock.h"
#include <map>
#include <string>
#include <sgx_trts.h>

static FILE *const nstdrandom = (FILE*)3;
static FILE *next_fd = nstdrandom + 1;
extern "C" {
extern void printf(const char *fmt, ...);
}

struct FileDescriptor;
typedef std::map<FILE*,FileDescriptor*> MapFiles;
static MapFiles files_byids;
struct FileDescriptor {
    FILE* id;
    std::string data;
    std::string::iterator it;
    bool writable_;

    FileDescriptor(): writable_(false) {
        id = next_fd++;
    }

    void set(const char *buff, size_t len) {
        data.assign(buff,len);
        it = data.begin();
        files_byids[id] = this;
    }

    void set_writable() {
        writable_ = true;
        files_byids[id] = this;
    }
};
typedef std::map<std::string, FileDescriptor> MapFilesByName;
static MapFilesByName files;

//------------------------------------------------------------------------------
void fmock_allow_writable( const char *fname ) {
    files[ std::string(fname) ].set_writable();
}

//------------------------------------------------------------------------------
void file_mock( const char *buff, size_t len, const char *fname ) {
    files[ std::string(fname) ].set(buff,len);
}

//------------------------------------------------------------------------------
FILE* fmock_open( const char *fname ) {
    std::string flname(fname);
    if( strlen(fname) > 2 && fname[0] == '.' && fname[1] == '/' )
        flname.erase(0,2);
    if( flname == "/dev/urandom" || flname == "/dev/random" ) return nstdrandom;
    if( files.find( flname ) == files.end() ) return NULL;
    return files[ flname ].id;
}

//------------------------------------------------------------------------------
int fmock_close( FILE *f ) {
    MapFiles::iterator fit = files_byids.find(f);
    if( fit == files_byids.end() ) return EBADF;
    files_byids.erase(fit);

    MapFilesByName::iterator it = files.begin();
    for(; it != files.end(); ++it )
        if( it->second.id == f ) { files.erase(it); break; }
    return 0;
}

//------------------------------------------------------------------------------
int fmock_feof(FILE *f) {
    return files_byids.find(f) == files_byids.end() ||
           files_byids[f]->it == files_byids[f]->data.end();
}

//------------------------------------------------------------------------------
int fmock_getc(FILE *f) {
    if( fmock_feof(f) ) return EOF;
    return (int)*(files_byids[f]->it)++;
}

//------------------------------------------------------------------------------
size_t fmock_fread(void *ptr, size_t size, size_t nmemb, FILE *f) {
    size_t ret = 0, pos = 0;
    if( f == nstdrandom ) {
        if( sgx_read_rand((unsigned char*)ptr,size*nmemb) == SGX_SUCCESS )
            ret = nmemb;
        return ret; 
    }

    MapFiles::iterator it;
    if( (it = files_byids.find(f)) == files_byids.end() ) return ret;

    FileDescriptor &fd = *it->second;
    char *p = (char*)ptr;
    while( fd.it != fd.data.end() && p - (char*)ptr < size*nmemb &&
           ( pos = fd.it - fd.data.begin() )+size <= fd.data.size() ) {
        memcpy( p++, fd.data.c_str() + pos, size );
        fd.it += size;
        ++ret;
    }
    return ret;
}

//------------------------------------------------------------------------------
size_t fmock_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f) {
    size_t ret = 0;
    MapFiles::iterator it;
    if( (it = files_byids.find(f)) == files_byids.end() ) return ret;

    FileDescriptor &fd = *it->second;
    fd.data += std::string((const char*)ptr,size*nmemb);
    return nmemb;
}

//------------------------------------------------------------------------------
size_t fmock_flush( char *buf, size_t sz, FILE *f ) {
    size_t ret = 0;
    MapFiles::iterator it;
    if( (it = files_byids.find(f)) == files_byids.end() ) return ret;

    ret = std::min( sz-1, it->second->data.size() );
    memcpy(buf, it->second->data.c_str(), ret );
    buf[ret] = '\0';
    return ret+1;
}

//------------------------------------------------------------------------------

