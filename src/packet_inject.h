/*
 * packet_inject.h
 *
 *  Created on: 06-Nov-2013
 *      Author: piyush
 */

#ifndef PACKET_INJECT_H_
#define PACKET_INJECT_H_

#include "packet_reader.h"
#include "network_interface_card.h"

int inject_packet( u_char* packet, size_t length ,
		enum PROTOCOL protocol, struct network_interface sourceinterface,
		struct network_interface destinterfacep);

void inject_tcp_packet();
void inject_udp_packet();
void inject_icmp_packet();
void inject_arp_packet();



#endif /* PACKET_INJECT_H_ */
