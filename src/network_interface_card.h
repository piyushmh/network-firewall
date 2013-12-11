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

struct arp_cache_entry;

struct network_interface{
	char devname[20];
	bpf_u_int32 mask;       /* netmask */
	bpf_u_int32 net;        /* IP */
	pcap_t *handle;
	u_char macaddress[ETHER_ADDR_LEN]; /*Mac address*/
	char macaddrstring[256];
	struct arp_cache_entry* arp_cache;
	pthread_rwlock_t lock;
};


struct pcap_handler_argument{
	struct network_interface* source;
	struct network_interface* dest;
	int is_pcap;
};

struct network_interface* get_network_interface(char* devname, char* macaddr);
void initialize_start_interfaces();
void print_network_interface(struct network_interface nic);
int match_ip_to_subnet_mask(char* ip, char* maskip, char* devip);
int match_ip_to_subnet_mask_integers(u_int32_t ip, int mask, u_int32_t devip);
struct network_interface* find_nic_from_ip(u_int32_t ip);
void initialize_default_interface();

struct network_interface* interface_list[10];
struct network_interface* default_interface;

#endif /* NETWORK_INTERFACE_H_ */
