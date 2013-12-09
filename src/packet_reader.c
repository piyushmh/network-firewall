#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/if_ether.h>

#include "packet_inject.h"
#include "packet_reader.h"
#include "apply_rule.h"
#include "network_interface_card.h"
#include "string_util.h"
#include "network_flow.h"

void print_ethernet_header(u_char* p){
	struct sniff_ethernet* packet = (struct sniff_ethernet*)p;
	printf("\nDestination Mac :%s\n", convertfrommacbytetomacstring(packet->ether_dhost));
	printf("Source Mac :%s\n", convertfrommacbytetomacstring(packet->ether_shost));
	printf("Ether type :%d\n", packet->ether_type);
	return;
}

void disassemble_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet){

	printf("%s\n", "Got a packet");
	struct sniff_ethernet *ethernet; /* The ethernet header */
	struct sniff_ip *ip; /* The IP header */
	struct sniff_tcp *tcp; /* The TCP header */
	struct sniff_udp *udp;
	u_char *payload; /* Packet payload */
	enum PROTOCOL protocol;
	u_int32_t packetlen = header->caplen;

	u_int size_network;
	u_int size_transport;

	u_char sourcemac[ETHER_ADDR_LEN];
	u_char destmac[ETHER_ADDR_LEN];
	struct network_interface* destnic;
	u_int32_t sourceip = 0;
	u_int32_t destip = 0;
	u_short sourceport = 0;
	u_short destport = 0;

	struct pcap_handler_argument* arg = (struct pcap_handler_argument*)args;
	printf("Reading packet from interface :%s\n", arg->source->devname);
	struct network_interface* sourcenic = arg->source;

	ethernet = (struct sniff_ethernet*)(packet);

	pp("Printing received ether header");
	print_ethernet_header((u_char*)packet);

	/* Now find which type of packet we got ICMP, TCP, UDP etc */
	memcpy(sourcemac, ethernet->ether_shost, ETHER_ADDR_LEN);
	memcpy(destmac, ethernet->ether_dhost, ETHER_ADDR_LEN);

	if(ethernet->ether_type == htons(ETH_P_ARP)){
		protocol = ARP;
		//fill these
	}else if (ethernet->ether_type == htons(ETH_P_IP)){

		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_network = IP_HL(ip)*4;
		if (size_network < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_network);
			return;
		}
		sourceip = ip->ip_src.s_addr;
		destip = ip->ip_dst.s_addr;

		if(ip->ip_p == IPPROTO_TCP){

			protocol = TCP;
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_network);
			size_transport = TH_OFF(tcp)*4;
			if (size_transport < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_transport);
				return;
			}
			sourceport = ntohs(tcp->th_sport);
			destport = ntohs(tcp->th_dport);
			payload = (u_char *)(packet + SIZE_ETHERNET + size_network + size_transport);

		}else if (ip->ip_p == IPPROTO_UDP){

			protocol = UDP;
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_network);
			sourceport = ntohs(udp->uh_sport);
			destport = ntohs(udp->uh_dport);

		}else if (ip->ip_p == IPPROTO_ICMP){

			protocol = ICMP;
			sourceport = 0;
			destport = 0;

		}else{
			//handle this later
		}
	}else{
		//handle this later
	}


	print_packet(sourceip,destip, sourceport, destport,sourcemac, destmac, protocol);
	/*
	sourceip = (uint32_t)inet_addr("192.168.0.14");
	destip = (uint32_t)inet_addr("192.168.0.10");
	sourceport = 23;
	destport = 34;
	hwaddr_aton("6c:71:d9:6a:74:46",sourcemac);
	*/

	if( protocol == ARP){
		//Add into arp table
	}


	if( memcmp(sourcemac, sourcenic->macaddress,ETHER_ADDR_LEN) == 0){//match
		pp("Injected packet found\n");
		return; //do nothing, this was a injected packet
	}

	destnic = find_nic_from_ip(destip);
	//print_mac_address(calcdestmac);

	if(destnic == NULL){
		pp("No network interface found with this IP, returning");
		return;
	}
	if(memcmp(destnic->macaddress, sourcenic->macaddress, ETHER_ADDR_LEN) == 0){
		pp("\nLocal area network packet found");
		return; //this mean this packet belong to the same local network
	}


	/*
	 * 1. If packet is part of open connection
	 * 		- Update flow,if packet is valid let it through otherwise block
	 * 2. Else, apply rules
	 * 		- If rules failes, block the packet
	 * 		- Else, rules passes, update flow.
	 * 			- If packet is valid, let it through
	 * 			- Otherwise block
	 */

	int res = 0;
	int update_flow = 0;
	int block = 1;

	if( protocol == TCP){
		if (pthread_rwlock_rdlock(&(flowmap_lock)) != 0){
			pp("Can't acquire read lock on flowmap, check what happened!!");
			return;
		}

		res = is_packet_part_of_open_connection(
				sourceip, destip, sourceport, destport);

		pthread_rwlock_unlock(&(flowmap_lock));

		if( res == 0){
			int rule_apply = traverse_rule_matrix(
					protocol, sourceip, destip, sourceport, destport,
					sourcemac, destmac);
			if( rule_apply == 1){
				update_flow = 1;
			}
		}else{
			update_flow = 1;
		}

		if( update_flow == 1){
			if (pthread_rwlock_wrlock(&(flowmap_lock)) != 0){
				pp("Can't acquire write lock on flowmap, check what happened!!");
				return;
			}
			int result = add_packet_to_network_flow(
					sourceip,destip, sourceport, destport, tcp->th_flags);

			pthread_rwlock_unlock(&(flowmap_lock));

			if( result ==1)
				block =0;
		}
	}else{ //ICMP, UDP
		int rule_apply = traverse_rule_matrix(
				protocol, sourceip, destip, sourceport, destport,
				sourcemac, destmac);
		printf("Inside packet reader, found packet ICMP/UDP with apply :%d\n", rule_apply);
		if( rule_apply == 1)
			block = 0;
	}

	//print_packet(sourceip,destip, sourceport, destport,sourcemac, destmac);

	if(block == 0){//ALLOW
		int res = inject_packet((u_char*)packet, packetlen, protocol,sourcenic, destnic, destip);
		if(res==1){
			printf("Injection done\n");
		}
	}else{ //BLOCK,throw away the packet
		printf("Packet blocked");
	}
	return;
}


void *read_packets(void *nic){
	//pp("here");
	struct network_interface* interface = (struct network_interface*) nic;
	//print_network_interface(*interface);
	//while(1){}
	struct pcap_handler_argument arg;
	arg.source = interface;
	arg.dest = NULL;
	int val = pcap_loop(interface->handle, -1, disassemble_packet, (void*)(&arg));
	printf("%d\n", val);
	/* And close the session */
	pcap_close(interface->handle);
	return 0;
}
