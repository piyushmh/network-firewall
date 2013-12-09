/*
 * string_util.h
 *
 *  Created on: 28-Nov-2013
 *      Author: piyush
 */

#ifndef STRING_UTIL_H_
#define STRING_UTIL_H_

#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include "packet_reader.h"

char *strstrip(char *s);
int hwaddr_aton(const char *txt, u_char *addr);

char* convertfromintegertoIP(u_int32_t ip);
char* convertfrommacbytetomacstring(u_char* mac);
void print_mac_address(u_char* mac);

void pp(char*x);
void pi(int x);
void print_packet(u_int32_t sourceip, u_int32_t destip,
		int sourceport, int destport, u_char* sourcemac, u_char* destmac,
		enum PROTOCOL protocol);

#endif /* STRING_UTIL_H_ */
