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

char *strstrip(char *s);
int hwaddr_aton(const char *txt, u_char *addr);

char* convertfromintergertoIP(u_int32_t ip);

void pp(char*x);
void pi(int x);
#endif /* STRING_UTIL_H_ */
