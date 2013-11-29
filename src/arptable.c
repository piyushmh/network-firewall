/*
 * arptable.c
 *
 *  Created on: 07-Nov-2013
 *      Author: piyush
 */

#include <string.h>
#include <stdlib.h>
#include "arptable.h"
#include "network_interface_card.h"

void arp_table_initialize(){

}


u_char etho_mac[6] = {0x0d, 0x0e, 0x0a, 0x0d, 0x00, 0x00};

//Hard coding this for time being
u_char* find_macaddr_network_interface(struct network_interface card){

	if(strcmp(card.devname, "eth0")==0){
		return etho_mac;
	}
	return NULL;
}

void find_macaddr_ip(){

}

