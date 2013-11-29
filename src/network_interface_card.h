/*
 * network_interface.h
 *
 *  Created on: 06-Nov-2013
 *      Author: piyush
 */

#ifndef NETWORK_INTERFACE_CARD_H_
#define NETWORK_INTERFACE_CARD_H_

#include <netinet/if_ether.h>
#include <pcap.h>



struct network_interface{
	char devname[20];
	bpf_u_int32 mask;       /* netmask */
	bpf_u_int32 net;        /* IP */
	pcap_t *handle;
	u_char macAddress[ETHER_ADDR_LEN]; /*Mac address*/
};

struct pcap_handler_argument{
	struct network_interface source;
	struct network_interface dest;
	//pcap_t *desthandle;
};


void initialize_interfaces();

/*
void print_network_interface(struct network_interface nic){
	printf("\nDevname :%s", nic.devname);
	printf("\nMacaddress :%s", nic.macAddress);

}

*/
#endif /* NETWORK_INTERFACE_H_ */
