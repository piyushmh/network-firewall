/*
 * network_flow.c
 *
 *  Created on: 02-Dec-2013
 *      Author: piyush
 */
#include "network_flow.h"
#include "string_util.h"


void initialize_network_flow(){
	flowmap = NULL;
}

struct host_node* makenewhostnode(
		u_int32_t sourceip){

	struct host_node* hostnode =
			(struct host_node*) malloc(sizeof(struct host_node));
	hostnode->source_ip  = sourceip;
	hostnode->total_succ_connections = 0;
	hostnode->total_reset = 0;
	hostnode->connmap = NULL;
	if (pthread_rwlock_init(&(hostnode->lock),NULL) != 0){
		pp("Cannot initialize read write lock for host node, exiting thread");
		exit(1);
	}
	return hostnode;
}

struct connection* makenewconnection(
		u_int32_t source_ip,
		u_int32_t dest_ip,
		u_short source_port,
		u_short dest_port){

	struct connection* conn =
			(struct connection*)malloc(sizeof(struct connection));
	conn->source_ip = source_ip;
	conn->dest_ip = dest_ip;
	conn->source_port = source_port;
	conn->dest_port  = dest_port;
	conn->key = source_ip + dest_ip + source_port + dest_port;
	conn->is_conn_active = 0;
	conn->is_conn_init = 0;
	conn->state = 0;
	return conn;
}

struct connection* find_connection_from_flowmap(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_short sourceport,
		const u_short destport){

	struct host_node* hostnode;
	HASH_FIND_INT(flowmap, &sourceip, hostnode);
	if( hostnode == NULL){
		return NULL;
	}

	struct connection* conn;
	u_int32_t key = sourceip + destip + sourceport + destport;
	HASH_FIND_INT(hostnode->connmap, &key, conn);
	if( conn == NULL){
		return NULL;
	}
	return conn;
}

int is_packet_open_connection_inner(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_short sourceport,
		const u_short destport){

	struct connection* conn = find_connection_from_flowmap(
			sourceip,destip,sourceport,destport);

	if(conn == NULL)
		return 0;

	if(conn->is_conn_init > 0)
		return 1;
	else
		return 0;
}


int is_packet_part_of_open_connection(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_short sourceport,
		const u_short destport){


	int ret = is_packet_open_connection_inner(
			sourceip,destip, sourceport,destport);
	if(ret == 1)
		return 1;

	ret = is_packet_open_connection_inner(
			destip, sourceip, destport, sourceport);
	if( ret == 1)
		return 1;
	else
		return 0;
}

int add_packet_to_network_flow(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_int32_t sourceport,
		const u_int32_t destport,
		const u_char flag){

	int retval = 0;

	struct connection* conn  =  find_connection_from_flowmap(
			sourceip, destip, sourceport,destport);

	if( conn == NULL){
		conn  = find_connection_from_flowmap(
				sourceip, destip, sourceport,destport);
	}

	if(conn == NULL){
		struct host_node* hostnode;
		HASH_FIND_INT(flowmap, &sourceip, hostnode);
		if(hostnode  == NULL){
			hostnode = makenewhostnode(sourceip);
			HASH_ADD_INT(flowmap,source_ip,hostnode);
		}
		conn = makenewconnection(sourceip,destip,sourceport, destport);
		HASH_ADD_INT(hostnode->connmap,key,conn);
	}

	//Here both hostnode and conn should be not null

}




