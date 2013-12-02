/*
 * arptable.h
 *
 *  Created on: 06-Nov-2013
 *      Author: piyush
 */

#ifndef ARPTABLE_H_
#define ARPTABLE_H_

#include <stddef.h>
#include "uthash.h"
#include "network_interface_card.h"

struct arp_cache_entry{
	u_int32_t ip; //Used for hashin
	u_char macaddress[ETHER_ADDR_LEN];
	clock_t timestamp;
	UT_hash_handle hh;
};


void add_entry_in_arp_cache(const u_int32_t ip,const u_char* macaddress,struct network_interface* nic);

struct arp_cache_entry* read_entry_from_arp_cache(
		const u_int32_t ip, struct network_interface* nic);

u_char* get_macaddr_from_ip_arpcache(const u_int32_t ip,
		struct network_interface* nic);

#endif /* ARPTABLE_H_ */
