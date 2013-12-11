/*
 * icmp_packet_handler.c
 *
 *  Created on: 09-Dec-2013
 *      Author: piyush
 */

#include <stdio.h>

#include "icmp_packet_handler.h"
#include "apply_rule.h"
#include "packet_inject.h"
#include "string_util.h"
#include "arptable.h"
#include "packet_reader.h"

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
		int is_pcap){

	struct sniff_ethernet* packet = (struct sniff_ethernet*)p;
	int rule_apply = traverse_rule_matrix(
			ICMP, sourceip, destip, sourceport, destport,
			sourcemac, destmac);

	if(rule_apply == 0){
		pp("ICMP packet blocked");
		return 0;
	}

	u_char* finalsourcemac = destnic->macaddress;
	u_char* finaldestmac = NULL;

	if(is_pcap == 0)
		finaldestmac = get_macaddr_from_ip_arpcache(destip, destnic);


	if( (finaldestmac == NULL) && (strcmp(destnic->devname, "wlan0")==0)){
		finaldestmac = (u_char*)malloc(ETHER_ADDR_LEN);
		hwaddr_aton("C0:CB:38:29:55:01", finaldestmac);
	}

	if(finaldestmac == NULL){
		pp("Can't fetch mac address from ARP cache, returning w/o injecting");
		return 0;
	}

	memcpy(packet->ether_shost,finalsourcemac, ETHER_ADDR_LEN);
	memcpy(packet->ether_dhost,finaldestmac, ETHER_ADDR_LEN);

	return inject_packet(packet,header, packetlen, destnic, is_pcap);
}

