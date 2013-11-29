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

void pp(char*x){ printf("\n%s",x); fflush(stdout);}
void pi(int x){ printf("\n%d",x); fflush(stdout);}



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

char* convertfromintergertoIP(u_int32_t ip){
	char *x = (char*)malloc(256*sizeof(char));
	struct in_addr ip_addr;
	ip_addr.s_addr = ip;
	strcpy(x,inet_ntoa(ip_addr));
	return x;
}
