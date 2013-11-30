/*
 * Apply_rule.h
 *
 *  Created on: 05-Nov-2013
 *      Author: piyush
 */

#ifndef APPLY_RULE_H_
#define APPLY_RULE_H_

#include "packet_reader.h"
#include "network_interface_card.h"

void initialize_rules();
int traverse_rule_matrix( enum PROTOCOL proto, u_int32_t sourceip,
	u_int32_t destip, u_short sourceport, u_short destport,
	u_char* sourcemac, u_char* destmac);

#endif /* APPLY_RULE_H_ */
