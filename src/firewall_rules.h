/*
 * firewall_rules.h
 *
 *  Created on: 05-Nov-2013
 *      Author: piyush
 */

#ifndef FIREWALL_RULES_H_
#define FIREWALL_RULES_H_

#include <stdio.h>
#include <stdlib.h>

enum ACTION{BLOCK, PASS};

enum RULE_ATTR { SRCIP, SRCPORT, DSTIP, DSTPORT, PRIORITY};

struct portrange{
	u_short start;
	u_short end;
};

struct firewall_rule{
	u_int32_t sourceip;
	u_int32_t destip;
	struct portrange sourceportrange;
	struct portrange destportrange;

	int sourceipmask;
	int destipmask;

	int priority;

	char sourcemacaddr[20];
	char destmacaddr[20];
	enum ACTION action;

	struct firewall_rule* next;
	struct firewall_rule* prev;

};

#endif /* FIREWALL_RULES_H_ */
