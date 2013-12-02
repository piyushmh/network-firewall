/*
 * network_flow.h
 *
 *  Created on: 02-Dec-2013
 *      Author: piyush
 */

#ifndef NETWORK_FLOW_H_
#define NETWORK_FLOW_H_

#include <pthread.h>

#include "uthash.h"


struct connection{
    u_int32_t source_ip;
    u_int32_t dest_ip;
    u_short source_port;
    u_short dest_port;
    int is_conn_init; //on if state >0
    int is_conn_active;//on if state > 2
    int is_conn_teardown;
    int state;
    /* States -
		0 - DEAD
		1 - SYN
		2 - SYNACK
		3 - ACK
		4 - FIN
		5 - FINFIN
		6 - FINACK
		7 - FINFINACK
		8 - TERMINATED (FINFINACKACK Done)
    */
    u_int32_t key;  //this would be source+ip+source_port+dest_port
    UT_hash_handle hh;
};

struct host_node{
    u_int32_t source_ip; //Hash key

    // this contains conction per port of the host
    struct connection* connmap;
    int total_succ_connections;
    int total_half_open;
    int total_reset;
    int anamoly_score;
    int dest_port_tracker[1<<16];
    time_t last_connection_time;
    long long packets_sent;
    //This controls the RW access to a instance of this structure
    pthread_rwlock_t lock;
    UT_hash_handle hh;
};

pthread_rwlock_t flowmap_lock;
struct host_node* flowmap;

void initialize_network_flow();

/*
 * Returns 1 if packet with parameters passed is part of a
 * open coneection. The check is done both ways, with connection
 * direction switched.
 * Returns 0 otherwise
 * */
int is_packet_part_of_open_connection(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_short sourceport,
		const u_short destport);

int add_packet_to_network_flow(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_int32_t sourceport,
		const u_int32_t destport,
		const u_char flag);


#endif /* NETWORK_FLOW_H_ */
