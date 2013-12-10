/*
 * packet_inject.c
 *
 *  Created on: 07-Nov-2013
 *      Author: piyush
 */

#include "packet_inject.h"
#include "packet_reader.h"
#include "string_util.h"

int inject_packet(
		struct sniff_ethernet* packet,
		size_t packetlen,
		struct network_interface* destnic){

	pp("\nInjecting the following ether header");
	//print_ethernet_header(packet);

	if(pcap_inject(destnic->handle, packet, packetlen) == -1){
		pcap_close(destnic->handle);
		printf("PCAP Injection failed");
		return 0;
	}

	return 1;

}



