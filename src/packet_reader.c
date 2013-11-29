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

void disassemble_packet(u_char *args, const struct pcap_pkthdr *header,
			const u_char *packet){

	printf("%s\n", "Got a packet");
	struct sniff_ethernet *ethernet; /* The ethernet header */
    struct sniff_ip *ip; /* The IP header */
    struct sniff_tcp *tcp; /* The TCP header */
    struct sniff_udp *udp;
    u_char *payload; /* Packet payload */
    enum PROTOCOL protocol;
    u_int32_t packetlen = header->len;

    u_int size_network;
    u_int size_transport;

    u_char sourcemac[ETHER_ADDR_LEN];
    u_char destmac[ETHER_ADDR_LEN];
    u_int32_t sourceip = 0;
    u_int32_t destip = 0;
    u_short sourceport = 0;
    u_short destport = 0;
    
    struct pcap_handler_argument* arg = (struct pcap_handler_argument*)args;
    printf("Reading packet from interface :%s\n", arg->source.devname);
    //printf("Injecting into interface :%s\n", arg->dest.devname);

    struct network_interface sourcenic = arg->source;

    ethernet = (struct sniff_ethernet*)(packet);

    //printf("%02X:%02X:%02X:%02X:%02X:%02X\n",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
    //printf("%02X:%02X:%02X:%02X:%02X:%02X\n",ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);

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

    sourceip = (uint32_t)inet_addr("60.50.40.33");
    destip = (uint32_t)inet_addr("55.255.255.252");
    sourceport = 23;
    destport = 34;
    int result = traverse_rule_matrix(
    		protocol, sourceip, destip, sourceport, destport,
    		sourcemac, destmac, arg->source);

    if(result == 1){//ALLOW
    	int res = inject_packet(packet, packetlen, protocol,arg->source,
    			arg->dest, destip);
    	if(res==1){
    		printf("Injection done\n");
    	}
    }else if ( result == 0){ //BLOCK,throw away the packet
    	printf("Packet blocked");
    }
	return;
}


void *read_packets(void *nic){
	pp("here");
	struct network_interface* interface = (struct network_interface*) nic;
	print_network_interface(*interface);
	//while(1){}
	struct pcap_handler_argument arg;
	arg.source = *interface;
	//int val = pcap_loop(interface->handle, 1, disassemble_packet, (void*)(&arg));
	//printf("%d\n", val);
	/* And close the session */
	pcap_close(interface->handle);
	return 0;
}
