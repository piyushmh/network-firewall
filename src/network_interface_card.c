/*
 * network_interface.cpp
 *
 *  Created on: 28-Nov-2013
 *      Author: piyush
 */

#include <stdio.h>
#include <stddef.h>
#include <pthread.h>
#include <string.h>

#include "network_interface_card.h"
#include "string_util.h"
#include "packet_reader.h"

void initialize_interfaces(){

	char interface_file_name[256] = "interfaces.txt";
	FILE *interfacefile = NULL;
	interfacefile = fopen(interface_file_name,"r");
	size_t len = 0;
	size_t read = 0;
	char *interface;
	while((read = getline(&interface, &len, interfacefile))!= -1){
		interface = strstrip(interface);
		if(strlen(interface)==0)
			continue;
		struct network_interface nic;
		char* saveptr;
		char* token;
		int ctr=0;
		for(;;interface=NULL){
			token = strtok_r(interface, " ", &saveptr);
			if( ctr==0){
				strcpy(nic.devname, token);
			}else if(ctr==1){
				strcpy(nic.macAddress,token);
			}else{
				//bogus
			}
			ctr++;
		}

		print_network_interface(nic);
		/*
		pthread_t thread;
		int x = pthread_create(
				&thread, NULL, read_packets, (void*)(&intf));
		pthread_join(thread, NULL);
		*/
	}

	return;
}
