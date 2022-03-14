/*
 * poll.h
 *
 *  Created on: 19 Jul 2018
 *      Author: sebastien
 */

#ifndef TRUSTED_INCLUDE_SYS_POLL_H_
#define TRUSTED_INCLUDE_SYS_POLL_H_

/* Type used for the number of file descriptors.  */
typedef unsigned long int nfds_t;

/* Data structure describing a polling request.  */
struct pollfd {
	int fd; /* File descriptor to poll.  */
	short int events; /* Types of events poller cares about.  */
	short int revents; /* Types of events that actually occurred.  */
};

#endif /* TRUSTED_INCLUDE_SYS_POLL_H_ */
