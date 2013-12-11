/*
 * pcap_file_handler.c
 *
 *  Created on: 10-Dec-2013
 *      Author: piyush
 */

#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include "pcap_file_handler.h"
#include "network_interface_card.h"
#include "packet_reader.h"

int handle_pcap_file(char* filename){

	initialize_default_interface();

	struct pcap_pkthdr* header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
	const u_char *packet; // The actual packet
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(filename, errbuf);   //call pcap library function

	if (handle == NULL) {
		printf("Couldn't open pcap file %s: \n", filename);
		return 0;
	}

	struct network_interface* interface =
			get_network_interface("wlan0","6c:71:d9:6a:74:45");
	struct pcap_handler_argument arg;
	arg.source = interface;
	arg.dest = NULL;
	arg.is_pcap = 1; //setting pcap mode on

	char* ofilename = (char*)malloc(256);
	strcpy(ofilename, "outdump");

	//pcap_t* pd = pcap_open_dead(DLT_EN10MB, 65535);
	if (ofilename != NULL){
		dumpfile=pcap_dump_open(handle, ofilename);
		if(dumpfile==NULL){
			printf("\nError opening output file\n");
			return 0;
		}
	}
	while (packet = pcap_next(handle,header)) {
		disassemble_packet((u_char*)&arg, header, packet);
	}
	pcap_close(handle);
	return 1;

}




