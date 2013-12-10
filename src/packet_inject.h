/*
 * packet_inject.h
 *
 *  Created on: 06-Nov-2013
 *      Author: piyush
 */

#ifndef PACKET_INJECT_H_
#define PACKET_INJECT_H_

#include "packet_reader.h"
#include "network_interface_card.h"

int inject_packet(
		struct sniff_ethernet* packet,
		size_t packetlen,
		struct network_interface* destnic);

#endif /* PACKET_INJECT_H_ */
