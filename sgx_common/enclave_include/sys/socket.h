/* Declarations of socket constants, types, and functions.
 Copyright (C) 1991-2018 Free Software Foundation, Inc.
 This file is part of the GNU C Library.

 The GNU C Library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 The GNU C Library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with the GNU C Library; if not, see
 <http://www.gnu.org/licenses/>.  */

#ifndef	_SYS_SOCKET_H
#define	_SYS_SOCKET_H	1

#include <sys/types.h>

#ifndef _BITS_SOCKADDR_H
#define _BITS_SOCKADDR_H	1

/* POSIX.1g specifies this type name for the `sa_family' member.  */
typedef unsigned short int sa_family_t;

/* This macro is used to declare the initial common members
 of the data types used for socket addresses, `struct sockaddr',
 `struct sockaddr_in', `struct sockaddr_un', etc.  */

#define	__SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family

#define __SOCKADDR_COMMON_SIZE	(sizeof (unsigned short int))

/* Size of struct sockaddr_storage.  */
#define _SS_SIZE 128

#endif	/* bits/sockaddr.h */

/* Structure describing a generic socket address.  */
struct sockaddr {
	__SOCKADDR_COMMON (sa_); /* Common data: address family and length.  */
	char sa_data[14]; /* Address data.  */
};

typedef uint32_t in_addr_t;
#define	INADDR_ANY		((in_addr_t) 0x00000000)
typedef uint16_t in_port_t;
struct in_addr {
	in_addr_t s_addr;
};

typedef struct sockaddr_in {
	__SOCKADDR_COMMON (sin_);
	in_port_t sin_port; /* Port number.  */
	struct in_addr sin_addr; /* Internet address.  */

	/* Pad to size of `struct sockaddr'.  */
	unsigned char sin_zero[sizeof(struct sockaddr) -
	__SOCKADDR_COMMON_SIZE - sizeof(in_port_t) - sizeof(struct in_addr)];
} sockaddr_in;

#define SOCK_STREAM 1
#define SOL_SOCKET	1
#define SO_REUSEADDR 2

#define	AF_INET	2
#define AF_INET6 10

#define NS_INADDRSZ 4
#define NS_IN6ADDRSZ 16
#define NS_INT16SZ 2

/* Duplicate info from sys/socket.h.  */
typedef uint32_t __socklen_t;

/* Type for length arguments in socket calls.  */
#ifndef __socklen_t_defined
typedef __socklen_t socklen_t;
# define __socklen_t_defined
#endif

struct addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	socklen_t ai_addrlen;
	struct sockaddr *ai_addr;
	char *ai_canonname;
	struct addrinfo *ai_next;
};

/* Structure for scatter/gather I/O.  */
struct iovec {
	void *iov_base; /* Pointer to data.  */
	size_t iov_len; /* Length of data.  */
};

struct msghdr {
	void *msg_name; /* Address to send to/receive from.  */
	socklen_t msg_namelen; /* Length of address data.  */

	struct iovec *msg_iov; /* Vector of data to send/receive into.  */
	size_t msg_iovlen; /* Number of elements in the vector.  */

	void *msg_control; /* Ancillary data (eg BSD filedesc passing). */
	size_t msg_controllen; /* Ancillary data buffer length.
	 !! The type should be socklen_t but the
	 definition of the kernel is incompatible
	 with this.  */

	int msg_flags; /* Flags on received message.  */
};

#endif /* sys/socket.h */
