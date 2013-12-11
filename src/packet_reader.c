#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/if_ether.h>

#include "packet_reader.h"
#include "apply_rule.h"
#include "network_interface_card.h"
#include "string_util.h"
#include "network_flow.h"
#include "icmp_packet_handler.h"
#include "structures.h"
#include "tcp_packet_handler.h"

void print_ethernet_header(u_char* p){
	struct sniff_ethernet* packet = (struct sniff_ethernet*)p;
	printf("\nDestination Mac :%s\n", convertfrommacbytetomacstring(packet->ether_dhost));
	printf("Source Mac :%s\n", convertfrommacbytetomacstring(packet->ether_shost));
	printf("Ether type :%d\n", packet->ether_type);
	return;
}

void disassemble_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet){

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
	int is_pcap = arg->is_pcap;
	struct network_interface* sourcenic = arg->source;
	printf("*****Got a packet on interface %s*****\n",arg->source->devname);
	ethernet = (struct sniff_ethernet*)(packet);

	memcpy(sourcemac, ethernet->ether_shost, ETHER_ADDR_LEN);
	memcpy(destmac, ethernet->ether_dhost, ETHER_ADDR_LEN);

	/* Now find which type of packet we got ICMP, TCP, UDP etc */
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

	if((is_pcap==0) && (memcmp(sourcemac, sourcenic->macaddress,ETHER_ADDR_LEN) == 0)){//match
		pp("Injected packet found\n");
		return; //do nothing, this was a injected packet
	}

	destnic = find_nic_from_ip(destip);

	if(destnic == NULL){
		pp("No network interface found with this IP, returning");
		return;
	}
	if((is_pcap ==0)&&(memcmp(destnic->macaddress, sourcenic->macaddress, ETHER_ADDR_LEN) == 0)){
		pp("\nLocal area network packet found");
		return; //this mean this packet belong to the same local network
	}

	if( protocol == TCP){
		handle_tcp_packet(
				(u_char*)packet,(struct pcap_pkthdr *) header,tcp,sourcenic, destnic,sourceip,
				destip,sourceport, destport, sourcemac, destmac, packetlen, is_pcap);
	}else if (protocol == UDP){

	}else if (protocol == ICMP){
		handle_icmp_packet(
				(u_char*)packet,(struct pcap_pkthdr *)header,sourcenic, destnic,sourceip,
				destip,sourceport, destport, sourcemac, destmac, packetlen, is_pcap);
	}else{

	}
	return;
}


void *read_packets(void *nic){
	struct network_interface* interface = (struct network_interface*) nic;
	struct pcap_handler_argument arg;
	arg.source = interface;
	arg.dest = NULL;
	arg.is_pcap = 0;
	int val = pcap_loop(interface->handle, -1, disassemble_packet, (void*)(&arg));
	printf("%d\n", val);
	pcap_close(interface->handle);
	return 0;
}

