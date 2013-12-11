/*
 * udp_packet_handler.h
 *
 *  Created on: 10-Dec-2013
 *      Author: piyush
 */

#ifndef UDP_PACKET_HANDLER_H_
#define UDP_PACKET_HANDLER_H_

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include "structures.h"
#include "network_interface_card.h"
#include <pcap.h>

int handle_udp_packet(
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

#endif /* UDP_PACKET_HANDLER_H_ */
