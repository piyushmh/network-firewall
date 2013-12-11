/*
 * string_util.c
 *
 *  Created on: 28-Nov-2013
 *      Author: piyush
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

#include "string_util.h"

#define DEBUG

char *strstrip(char *s){
	size_t size;
	char *end;

	size = strlen(s);

	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	while (*s && isspace(*s))
		s++;

	return s;
}

void pp(char*x){
#ifdef DEBUG
	printf("%s\n",x); fflush(stdout);
#endif
}

void pi(int x){
#ifdef DEBUG
	printf("%d\n",x); fflush(stdout);
#endif
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

void print_packet(u_int32_t sourceip, u_int32_t destip,
		int sourceport, int destport, u_char* sourcemac, u_char* destmac,
		enum PROTOCOL protocol){
	printf("\nSouceIP :%s\n", convertfromintegertoIP(sourceip));
	printf("DestIP :%s\n", convertfromintegertoIP(destip));
	printf("Souceport :%d\n", sourceport);
	printf("Destport :%d\n", destport);
	printf("SourceMac :%s\n", convertfrommacbytetomacstring(sourcemac));
	printf("DestMac :%s\n", convertfrommacbytetomacstring(destmac));
	printf("Protocol :%d\n", protocol);
	fflush(stdout);

}

void print_mac_address(u_char* mac){
	printf("\n%02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	fflush(stdout);
}

char* convertfrommacbytetomacstring(u_char* mac){
	char *ret = (char*)malloc(256);
	sprintf(ret,"%02X:%02X:%02X:%02X:%02X:%02X",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return ret;
}

char* convertfromintegertoIP(u_int32_t ip){
	char *x = (char*)malloc(256*sizeof(char));
	struct in_addr ip_addr;
	ip_addr.s_addr = ip;
	strcpy(x,inet_ntoa(ip_addr));
	return x;
}
