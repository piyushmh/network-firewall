/*
 * tcp_packet_handler.h
 *
 *  Created on: 09-Dec-2013
 *      Author: piyush
 */

#ifndef TCP_PACKET_HANDLER_H_
#define TCP_PACKET_HANDLER_H_

#include <stddef.h>
#include "structures.h"
#include "network_interface_card.h"
#include <pcap.h>

int handle_tcp_packet(
		u_char* p,
		struct pcap_pkthdr *header,
		struct sniff_tcp* tcp,
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

#endif /* TCP_PACKET_HANDLER_H_ */
