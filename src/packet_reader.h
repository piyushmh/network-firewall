#ifndef PACKET_READER_H
#define PACKET_READER_H


#include "firewall_rules.h"
#include "structures.h"


void* read_packets(void* nic);

void read_pcap_file(char* filname);

void disassemble_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet);

#endif /* PACKET_READER_H */
