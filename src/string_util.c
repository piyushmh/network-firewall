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

void pp(char*x){ printf("\n%s",x);}
