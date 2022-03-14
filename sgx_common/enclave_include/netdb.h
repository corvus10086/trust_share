/*
 * netdb.h
 *
 *  Created on: 19 Jul 2018
 *      Author: sebastien
 */

#ifndef TRUSTED_INCLUDE_NETDB_H_
#define TRUSTED_INCLUDE_NETDB_H_

#include <sys/socket.h>

/* Description of data base entry for a single host.  */
struct hostent
{
  char *h_name;                 /* Official name of host.  */
  char **h_aliases;             /* Alias list.  */
  int h_addrtype;               /* Host address type.  */
  int h_length;                 /* Length of address.  */
  char **h_addr_list;           /* List of addresses from name server.  */
#ifdef __USE_MISC
# define        h_addr  h_addr_list[0] /* Address, for backward compatibility.*/
#endif
};

#endif /* TRUSTED_INCLUDE_NETDB_H_ */
