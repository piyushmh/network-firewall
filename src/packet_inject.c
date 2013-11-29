/*
 * packet_inject.c
 *
 *  Created on: 07-Nov-2013
 *      Author: piyush
 */

#include <string.h>
#include "packet_inject.h"
#include "packet_reader.h"
#include "arptable.h"

int inject_packet( u_char* packet, size_t length ,
		enum PROTOCOL protocol, struct network_interface sourceinterface,
		struct network_interface destinterface, u_int32_t destip){

	struct sniff_ethernet* eth = (struct sniff_ethernet*)packet;

	u_char* ethernetcard = "74:d0:2b:47:de:17";
	u_char nsrcMacAddress[ETHER_ADDR_LEN];
	hwaddr_aton(ethernetcard, nsrcMacAddress);
	//u_char* sourcemac = find_macaddr_network_interface(destinterface);
	memcpy(eth->ether_shost,nsrcMacAddress, ETHER_ADDR_LEN);
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",nsrcMacAddress[0],nsrcMacAddress[1],nsrcMacAddress[2],nsrcMacAddress[3],nsrcMacAddress[4],nsrcMacAddress[5]);
	if(pcap_inject(destinterface.handle, packet, length) == -1){
		pcap_close(destinterface.handle);
		printf("PCAP Injection failed");
		return 0;
	}

	return 1;

}



static int hex2num(char c)
{
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}


int hex2byte(const char *hex)
{
        int a, b;
        a = hex2num(*hex++);
        if (a < 0)
                return -1;
        b = hex2num(*hex++);
        if (b < 0)
                return -1;
        return (a << 4) | b;
}


int hwaddr_aton(const char *txt, u_char *addr)
{
    int i;
    for (i = 0; i < 6; i++)
    {
        int a, b;

        a = hex2num(*txt++);
        if (a < 0)
            return -1;
        b = hex2num(*txt++);
        if (b < 0)
            return -1;
        *addr++ = (a << 4) | b;
        if (i < 5 && *txt++ != ':')
                return -1;
}
    return 0;
}
