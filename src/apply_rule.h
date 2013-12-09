/*
 * Apply_rule.h
 *
 *  Created on: 05-Nov-2013
 *      Author: piyush
 */

#ifndef APPLY_RULE_H_
#define APPLY_RULE_H_

#include <pthread.h>

#include "packet_reader.h"
#include "network_interface_card.h"
#include "firewall_rules.h"

void initialize_rules();

int add_rule_to_list_external(char* rule);

int mark_rule_as_inactive(int ruleid);

void print_all_rules();

pthread_rwlock_t rulelist_lock;

int traverse_rule_matrix( enum PROTOCOL proto, u_int32_t sourceip,
	u_int32_t destip, u_short sourceport, u_short destport,
	u_char* sourcemac, u_char* destmac);

#endif /* APPLY_RULE_H_ */
