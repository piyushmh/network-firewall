/*
 * network_interface.cpp
 *
 *  Created on: 28-Nov-2013
 *      Author: piyush
 */

#include <stdio.h>
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "network_interface_card.h"
#include "string_util.h"
#include "packet_reader.h"

struct network_interface* get_network_interface(char* devname, char* macaddr);

void initialize_start_interfaces(){

	char interface_file_name[] = "/home/piyush/dcn/project_final/NetworkFirewall/src/interfaces.txt";
	FILE *interfacefile = NULL;
	interfacefile = fopen(interface_file_name,"r");
	if( interfacefile == NULL){
		printf("Cannot read interface information, exiting");
		return;
	}
	size_t len = 0;
	size_t read = 0;
	char *interface;

	pthread_t threads[10];
	int numthreads = 0;

	while((read = getline(&interface, &len, interfacefile))!= -1){
		interface = strstrip(interface);
		if(strlen(interface)==0)
			continue;
		char devname[256];
		char macaddr[256];
		char* saveptr;
		char* token;
		int ctr=0;
		for(;;interface=NULL){
			token = strtok_r(interface, " ", &saveptr);
			if(token==NULL)
				break;

			if( ctr==0){
				strcpy(devname, token);
			}else if(ctr==1){
				strcpy(macaddr,token);
			}else{
				//bogus
			}
			ctr++;
		}

		struct network_interface* nic = get_network_interface(devname,macaddr);
		interface_list[numthreads] = nic;
		pthread_create(&threads[numthreads++], NULL, read_packets, (void*)nic);

	}

	interface_list[numthreads] = NULL;
	int i;
	for(i=0; i< numthreads;i++){
		pthread_join(threads[i],NULL);
	}

	printf("Main: program completed. Exiting.\n");
	pthread_exit(NULL);
}

struct network_interface* get_network_interface(char* devname, char* macaddr){

	struct network_interface* nic =
			(struct network_interface*) malloc(sizeof(struct network_interface));

	strcpy(nic->devname, devname);
	strcpy(nic->macaddrstring, macaddr);

	pcap_t *sourcehandle;         /* Source Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
	struct bpf_program fp;      /* The compiled filter */
	char filter_exp[] = "tcp";  /* The filter expression */
	bpf_u_int32 mask;           /* Our net mask */
	bpf_u_int32 net;            /* Our IP */

	/* Find the properties for the device */
	if (pcap_lookupnet(nic->devname, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get net mask for device %s: %s\n", nic->devname, errbuf);
		net = 0;
		mask = 0;
	}
	nic->mask = mask;
	nic->net = net;

	/* Open the session in promiscuous mode */
	sourcehandle = pcap_open_live(nic->devname, BUFSIZ, 1, 1000, errbuf);
	if (sourcehandle == NULL) {
		fprintf(stderr, "Couldn't open source device %s: %s\n", nic->devname, errbuf);
		exit(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(sourcehandle, &fp, filter_exp, 0, nic->net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(sourcehandle));
		exit(2);
	}
	if (pcap_setfilter(sourcehandle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(sourcehandle));
		exit(2);
	}
	nic->handle = sourcehandle;

	u_char* macAddress = (u_char*)malloc(ETHER_ADDR_LEN*sizeof(u_char));
	hwaddr_aton(nic->macaddrstring, macAddress);
	memmove(nic->macaddress, macAddress, ETHER_ADDR_LEN);
	nic->arp_cache = NULL; //Initialize the arp cache to null, UTHASH would initialize it properly
	if (pthread_rwlock_init(&(nic->lock),NULL) != 0){
		pp("Cannot initialize read write lock for device, exiting thread");
		exit(1);
	}
	return nic;

}

int match_ip_to_subnet_mask_integers(u_int32_t ip, int mask, u_int32_t devip){
	//pp("VVV");
	//pi(ip);
	//pi(mask);
	//pi(devip);
	int m= ((1L)<<(mask))-1;
	if((ip&m) == (devip&m))
		return 1;
	else
		return 0;
}

int match_ip_to_subnet_mask(char* ip, char* maskip, char* devip){
	struct in_addr x,y,z;
	inet_aton(maskip,&x);
	int maskbits;
	int mask = ntohl(x.s_addr);
	for ( maskbits=32 ; (mask & (1L<<(32-maskbits))) == 0 ; maskbits-- );
	inet_aton(ip,&y);
	inet_aton(devip,&z);
	if( match_ip_to_subnet_mask_integers(y.s_addr,maskbits,z.s_addr ))
		return 1;
	else
		return 0;

}

struct network_interface* find_nic_from_ip(u_int32_t ip){
	int ctr = 0;
	struct network_interface* iter = interface_list[ctr];
	while(iter!=NULL){
		if(match_ip_to_subnet_mask(convertfromintegertoIP(ip)
				, convertfromintegertoIP(iter->mask), convertfromintegertoIP(iter->net)) == 1){
			return iter;
		}
		iter = interface_list[++ctr];
	}
	return iter;
}

void print_network_interface(struct network_interface nic){
	printf("\nDevname :%s", nic.devname);
	printf("\nMacaddress :%s", nic.macaddrstring);
	printf("\nMask: %s", convertfromintegertoIP(nic.mask));
	printf("\nNet :%s", convertfromintegertoIP(nic.net));
	fflush(stdout);
}
