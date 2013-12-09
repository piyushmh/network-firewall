/*
 * arptable.c
 *
 *  Created on: 07-Nov-2013
 *      Author: piyush
 */

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "arptable.h"
#include "network_interface_card.h"
#include "uthash.h"
#include "string_util.h"

#define CACHE_VALID_TIME_SEC 60


struct arp_cache_entry* make_arp_cache_entry(const u_int32_t ip, const u_char* macaddress){
	struct arp_cache_entry* entry =
			(struct arp_cache_entry*)malloc(sizeof(struct arp_cache_entry));
	entry->ip = ip;
	memcpy(entry->macaddress, macaddress,ETHER_ADDR_LEN);
	entry->timestamp = time(NULL);
	return entry;
}

/*Add entry in the ARP cache present in the NIC passed
 * Duplicacy check is made internally*/
void add_entry_in_arp_cache(const u_int32_t ip,const u_char* macaddress,
		struct network_interface* nic){

	if (pthread_rwlock_wrlock(&(nic->lock)) != 0){
		pp("Cant acquire write lock on the arp cache");
	}
	struct arp_cache_entry* entry = NULL;
	HASH_FIND_INT(nic->arp_cache, &ip, entry);
	if( entry == NULL){
		entry = make_arp_cache_entry(ip, macaddress);
		HASH_ADD_INT(nic->arp_cache,ip,entry);
	}
	memcpy(entry->macaddress, macaddress, ETHER_ADDR_LEN);
	entry->timestamp = time(NULL);
	pthread_rwlock_unlock(&(nic->lock));
}

int get_macaddrr_arp_request(struct network_interface* nic, const u_int32_t ip){

	int retval = 0;
	FILE* f;
	char command[256];
	char* ipstring = convertfromintegertoIP(ip);
	sprintf(command, "arping -I %s -c 1 -w 0.01 %s | awk 'NR==2' | awk '{print $5}'", nic->devname, ipstring);
	f = popen(command, "r");
	if(!f){
		pp("Error while sending arp ping, check!!");
	}else{
		char output[256];
		fscanf(f, "%s", output);
		if(strlen(output) == 19){ //This means a valid response
			int i;
			for(i=1;i<=19;i++){
				output[i-1] = output[i];
			}
			output[17] = '\0';
			u_char* macaddress = (u_char*)malloc(sizeof(ETHER_ADDR_LEN));
			hwaddr_aton(output,macaddress);
			add_entry_in_arp_cache(ip, macaddress, nic);
			retval = 1;
		}
	}

	if(pclose(f)!=0){
		pp("Error while opening the output stream while sending the arp packet");
	}
	return retval;
}


/*Returns an ARP entry if its is found, other wise returns NULL*/
struct arp_cache_entry* read_entry_from_arp_cache(
		const u_int32_t ip, struct network_interface* nic){

	if (pthread_rwlock_rdlock(&(nic->lock)) != 0){
		pp("Cant acquire read lock on the arp cache");
	}
	struct arp_cache_entry* entry = NULL;
	HASH_FIND_INT(nic->arp_cache, &ip, entry);

	pthread_rwlock_unlock(&(nic->lock));
	return entry;

}

/* Returns mac address if present in the cache,
 * otherwise fetches the mac address through ARP call,
 * inserts it into the cache and returns it
 * Returns NULL otherwise*/
u_char* get_macaddr_from_ip_arpcache(const u_int32_t ip,
		struct network_interface* nic){

	//printf("Trying to get mac address of %s from interface %s \n",convertfromintegertoIP(ip), nic->devname);
	int arp_call_needed = 0;
	int valid_mac_found  = 0;
	u_char* macaddrret = macaddrret = (u_char*)malloc(sizeof(ETHER_ADDR_LEN));

	struct arp_cache_entry* entry = read_entry_from_arp_cache(ip,nic);

	if( entry == NULL){
		arp_call_needed = 1;
	}else{
		time_t currtime = time(NULL);
		long long timediff = difftime(currtime,entry->timestamp);
		//printf("Cache address: %p\n", entry);
		//printf("\nC: %ld  S: %ld Diff :%ld\n", currtime, entry->timestamp, timediff);
		if( timediff > 60){
			arp_call_needed = 1;
		}
	}
	if( arp_call_needed == 0){
		pp("Successfully fetched from cache");
		valid_mac_found = 1;
		memcpy(macaddrret, entry->macaddress, ETHER_ADDR_LEN);
	}else{
		pp("Sending ARP request to get MAC");
		get_macaddrr_arp_request(nic, ip);
		entry = read_entry_from_arp_cache(ip,nic);
		if( entry != NULL){
			valid_mac_found = 1;
			memcpy(macaddrret, entry->macaddress, ETHER_ADDR_LEN);
		}
	}

	if (valid_mac_found == 1)
		return macaddrret;
	else
		return NULL;
}

