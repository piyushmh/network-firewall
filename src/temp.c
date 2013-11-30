#include "network_interface_card.h"
#include "arptable.h"
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>
#include "string_util.h"

int main(){

	char x[]= "74:d0:2b:47:de:17";
	u_char* c = (u_char*)malloc(sizeof(6));
	hwaddr_aton(x,c);
	printf("%s\n", convertfrommacbytetomacstring(c));
	struct network_interface* nic = (struct network_interface*)malloc(sizeof(struct network_interface));
	nic->arp_cache = NULL;
	strcpy(nic->devname,"wlan0");
	pthread_rwlock_init(&(nic->lock),NULL);
	struct in_addr s;
	char str[] = "192.168.0.1";
	inet_pton(AF_INET, str,&s);
	u_char* v = get_macaddr_from_ip_arpcache(s.s_addr,nic);
	printf("%s\n",v);
	v = get_macaddr_from_ip_arpcache(s.s_addr,nic);
	printf("%s\n",v);

	struct arp_cache_entry* q;
	for (q = nic->arp_cache; q!=NULL; q= q->hh.next){
		printf("%d %s %ld\n", q->ip, convertfrommacbytetomacstring(q->macaddress), q->timestamp);
	}
	return 0;
}
