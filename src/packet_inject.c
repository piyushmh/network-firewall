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

	struct sniff_ethernet* eth = (struct sniff_ethernet*)packet;

	u_char* finalsourcemac = destinterface->macaddress;
	u_char* finaldestmac = get_macaddr_from_ip_arpcache(destip, destinterface);
	memcpy(eth->ether_shost,finalsourcemac, ETHER_ADDR_LEN);
	memcpy(eth->ether_dhost,finaldestmac, ETHER_ADDR_LEN);
    //printf("%02X:%02X:%02X:%02X:%02X:%02X\n",nsrcMacAddress[0],nsrcMacAddress[1],nsrcMacAddress[2],nsrcMacAddress[3],nsrcMacAddress[4],nsrcMacAddress[5]);
	if(pcap_inject(destinterface->handle, packet, length) == -1){
		pcap_close(destinterface->handle);
		printf("PCAP Injection failed");
		return 0;
	}

	return 1;

}


