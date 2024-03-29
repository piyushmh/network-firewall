/*
 * tcp_packet_handler.c
 *
 *  Created on: 09-Dec-2013
 *      Author: piyush
 */

#include <pthread.h>

#include "tcp_packet_handler.h"
#include "network_flow.h"
#include "string_util.h"
#include "apply_rule.h"
#include "arptable.h"
#include "packet_inject.h"

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
		int is_pcap){

	int retval = 0;
	int res = 0;
	int update_flow = 0;
	int block  = 1;


	/*
	 * 1. If packet is part of open connection
	 * 		- Update flow,if packet is valid let it through otherwise block
	 * 2. Else, apply rules
	 * 		- If rules failes, block the packet
	 * 		- Else, rules passes, update flow.
	 * 			- If packet is valid, let it through
	 * 			- Otherwise block
	 */

	struct sniff_ethernet* packet = (struct sniff_ethernet*)p;
	if (pthread_rwlock_rdlock(&(flowmap_lock)) != 0){
		pp("Can't acquire read lock on flowmap, check what happened!!");
		return 0;
	}
	res = is_packet_part_of_open_connection(
			sourceip, destip, sourceport, destport, is_pcap);
	pthread_rwlock_unlock(&(flowmap_lock));

	if( res == 0 || res == 1){
		int rule_apply = traverse_rule_matrix(
				TCP, sourceip, destip, sourceport, destport,
				sourcemac, destmac);
		if( rule_apply == 1){
			update_flow = 1;
		}
	}else if(res==2 || res ==4){
		update_flow = 1;
	}else if(res == 3){
		int rule_apply = traverse_rule_matrix(
				TCP, sourceip, destip, sourceport, destport,
				sourcemac, destmac);
		if( rule_apply == 1){
			update_flow = 1;
		}
	}

	if( update_flow == 1){
		if (pthread_rwlock_wrlock(&(flowmap_lock)) != 0){
			pp("Can't acquire write lock on flowmap, check what happened!!");
			return 0;
		}
		int result = 0;
		if( res == 0 || res == 1 || res ==2){
			pp("Adding straight packet\n");
			result = add_packet_to_network_flow(
					sourceip,destip, sourceport, destport, tcp->th_flags, is_pcap);
		}else if (res ==3 || res==4	){
			pp("Adding reverse packet packet\n");
			result = add_packet_to_network_flow(
					destip,sourceip, destport, sourceport, tcp->th_flags, is_pcap);
		}else{

		}
		pthread_rwlock_unlock(&(flowmap_lock));

		if( result ==1)
			block =0;
	}

	if(block==0){
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

		retval =  inject_packet(packet, header, packetlen, destnic, is_pcap);
	}else{
		pp("Packed blocked\n");
	}
	return retval;
}
