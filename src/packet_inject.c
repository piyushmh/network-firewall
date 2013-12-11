/*
 * packet_inject.c
 *
 *  Created on: 07-Nov-2013
 *      Author: piyush
 */

#include "packet_inject.h"
#include "packet_reader.h"
#include "string_util.h"
#include "pcap_file_handler.h"

int inject_packet(
		struct sniff_ethernet* packet,
		struct pcap_pkthdr *header,
		size_t packetlen,
		struct network_interface* destnic,
		int is_pcap){

	pp("\nInjecting the following ether header");

	if(is_pcap == 1){
		pcap_dump((u_char*)dumpfile,header,(u_char*)packet);
		return 1;
	}

	if(pcap_inject(destnic->handle, packet, packetlen) == -1){
		pcap_close(destnic->handle);
		printf("PCAP Injection failed");
		return 0;
	}

	return 1;

}



