#ifndef _LIBCPP_MOCK_H_
#define _LIBCPP_MOCK_H_

#include <string>
#include <libc_mock/libc_proxy.h>

namespace std {

using ::lconv;
using ::localeconv;

struct ostream {};
struct istream {};

template< typename T >
inline std::string to_string( T x ) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%d", x);
    return std::string(buf);
}

template<>
inline std::string to_string( long unsigned int x ) {
    char buf[100];
    snprintf(buf, sizeof(buf), "%lu", x);
    return std::string(buf);
}

struct stringstream {
    stringstream () {}
    stringstream ( const std::string &s ) : buffer(s) {}

    void write( const char *p, size_t sz ) {
        buffer += std::string(p,sz);
    }

    void read( char *out, size_t sz ) {
        size_t rd = 0;
        memcpy(out, buffer.c_str(), rd=std::min(sz,buffer.size()) );
        buffer.erase(0,rd);
    }

    stringstream& operator<< (const std::string &in ) {
        buffer += in;
        return *this;
    }

    std::string str() { return buffer; }

    std::string buffer;
};

inline bool getline(stringstream &ss, std::string &s, char delim) {
    size_t nl = ss.buffer.find(delim);
    if( nl == std::string::npos ) {
        if( !ss.buffer.empty() ) {
            s = ss.buffer;
            ss.buffer.clear();
            return true;
        } else {
            return false;
        }
    }
    s = ss.buffer.substr(0,nl);
    ss.buffer.erase(0,nl+1);
    return true;
}

}

#endif

