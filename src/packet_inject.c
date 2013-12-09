/*
 * packet_inject.c
 *
 *  Created on: 07-Nov-2013
 *      Author: piyush
 */

#include <string.h>
#include "packet_inject.h"
#include "packet_reader.h"
#include "arptable.h"
#include "string_util.h"

int inject_packet( u_char* packet, size_t length ,
		enum PROTOCOL protocol, struct network_interface* sourceinterface,
		struct network_interface* destinterface, u_int32_t destip){

	//printf("\nInject_packet : Inject packet into %s of IP :%s", destinterface->devname, convertfromintegertoIP(destip));
	struct sniff_ethernet* eth = (struct sniff_ethernet*)packet;

	u_char* finalsourcemac = destinterface->macaddress;
	u_char* finaldestmac = get_macaddr_from_ip_arpcache(destip, destinterface);

	if(finaldestmac == NULL){
		//printf("XX:%s %s", convertfromintegertoIP(destinterface->net), convertfromintegertoIP(destip));
		pp("Can't fetch mac address from ARP cache, returning w/o injecting");
		return 0;
	}

	memcpy(eth->ether_shost,finalsourcemac, ETHER_ADDR_LEN);
	memcpy(eth->ether_dhost,finaldestmac, ETHER_ADDR_LEN);

	pp("\nInjecting the following ether header");
	//print_ethernet_header(packet);

	if(pcap_inject(destinterface->handle, packet, length) == -1){
		pcap_close(destinterface->handle);
		printf("PCAP Injection failed");
		return 0;
	}

	return 1;

}


