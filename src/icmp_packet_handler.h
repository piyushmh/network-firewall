/*
 * icmp_packet_handler.h
 *
 *  Created on: 09-Dec-2013
 *      Author: piyush
 */

#ifndef ICMP_PACKET_HANDLER_H_
#define ICMP_PACKET_HANDLER_H_

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include "network_interface_card.h"

int handle_icmp_packet(
		u_char* p,
		struct pcap_pkthdr *header,
		struct network_interface* sourcenic,
		struct network_interface* destnic,
		u_int32_t sourceip,
		u_int32_t destip,
		u_short sourceport,
		u_short destport,
		u_char* sourcemac,
		u_char*destmac,
		int packetlen,
		int is_pcap);

#endif /* ICMP_PACKET_HANDLER_H_ */
