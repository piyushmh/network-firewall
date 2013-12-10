/*
 * network_flow.c
 *
 *  Created on: 02-Dec-2013
 *      Author: piyush
 */

#include <assert.h>

#include "network_flow.h"
#include "string_util.h"
#include "packet_reader.h"

/* Used internally to identify packet type*/
typedef enum { SYN, SYNACK, ACK, FIN, FINACK, RST, EMPTY, UNKNOWN} FLAG;

void initialize_network_flow(){
	flowmap = NULL;
	if (pthread_rwlock_init(&(flowmap_lock),NULL) != 0){
		pp("Cannot initialize read write lock for host node, exiting thread");
		exit(1);
	}
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
	conn->is_conn_teardown = 0;
	conn->state = 0;
	return conn;
}

struct host_node* find_host_node_from_flowmap(
		const u_int32_t sourceip){

	struct host_node* hostnode;
	HASH_FIND_INT(flowmap, &sourceip, hostnode);
	return hostnode;
}

struct connection* find_connection_from_flowmap(
		struct host_node* hostnode,
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_short sourceport,
		const u_short destport){

	struct connection* conn;
	u_int32_t key = sourceip + destip + sourceport + destport;
	HASH_FIND_INT(hostnode->connmap, &key, conn);
	return conn;
}

/*
 * 0 - No connection
 * 1 - Init connection
 * 2 - Active connection
 */
int is_packet_open_connection_inner(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_short sourceport,
		const u_short destport){

	struct host_node* hostnode = find_host_node_from_flowmap(sourceip);
	if(hostnode== NULL)
		return 0;
	struct connection* conn = find_connection_from_flowmap(
			hostnode ,sourceip,destip,sourceport,destport);

	if(conn == NULL)
		return 0;

	if(conn->is_conn_active > 0)
		return 2;
	else if( conn->is_conn_init > 0)
		return 1;
	else
		return 0;
}


/*
 * 0 - No connection
 * 1 - Forward connection but init stage
 * 2 - Forward connection active stage
 * 3 - Reverse connection init age
 * 4 - Reverse connection active stage
 */
int is_packet_part_of_open_connection(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_short sourceport,
		const u_short destport){


	int ret = is_packet_open_connection_inner(
			sourceip,destip, sourceport,destport);
	if(ret != 0)
		return ret;

	ret = is_packet_open_connection_inner(
			destip, sourceip, destport, sourceport);
	if( ret == 1)
		return 3; //this means reverse source and destination
	else if(ret==2)
		return 4;
	else
		return 0;
}

int update_flow_with_packet(
		struct connection* conn,
		FLAG f){

	int flow_updated = 1;

	if( f == SYN){
		if(conn->is_conn_init == 1){
			//Duplicate SYN, maybe retranmission, let it be :)
			pp("Syn on open connection detected");
		}else{
			conn->is_conn_init = 1;
			conn->state = 1;
		}
	}else if( f == SYNACK){
		if( conn->is_conn_init == 1 ){//valid case
			if(conn->state == 1)
				conn->state = 2;
			else{
				//might be retransmission, we have seen that a lot
			}
		}else{
			flow_updated = 0;
		}
	}else if( f == ACK){

		if( conn->is_conn_init == 1){
			if(conn->state == 2){
				conn->state = 3;
				conn->is_conn_active = 1;
			}else if(conn->state == 3){
				//this means data transfer
			}
			else if (conn->is_conn_teardown == 1 && conn->state == 4)
				conn->state = 6;
			else if (conn->is_conn_teardown == 1 && conn->state == 5)
				conn->state = 7;
			else if (conn->is_conn_teardown == 1 && conn->state == 7)
				conn->state = 8;
			else {
				//Maybe be a retransmission
			}
		}else{
			flow_updated = 0;
		}

	}else if( f == FIN){

		if (conn->is_conn_active == 1){
			if (conn->state == 3){
				conn->state = 4;
				conn->is_conn_teardown = 1;
			}else if ((conn->is_conn_teardown == 1) && (conn->state == 4)){
				conn->state = 5;
			}else if ((conn->is_conn_teardown == 1) && (conn->state == 6)){
				conn->state = 7;
			}
		}else{
			flow_updated = 0;
		}

	}else if (f == FINACK){

		if( conn->is_conn_active == 1){
			if(conn->state == 3){
				conn->state = 4;
				conn->is_conn_teardown = 1;
			}
			else if( conn->state == 4){
				conn->state = 7;
			}else if (conn->state == 6){
				conn->state = 8;
			}

		}else{
			flow_updated = 0;
		}

	}else if ( f == RST){
		if( conn->is_conn_init == 1){
			conn->state = 8;
		}else
			flow_updated = 0;
	}

	printf("Network state updated to :%d with packet %d and u:%d \n", conn->state, f,flow_updated);
	return flow_updated;
}


void remove_connection(
		struct host_node* hostnode,
		struct connection* conn){

	HASH_DEL(hostnode->connmap, conn);
	free(conn);

	if( hostnode->connmap == NULL){
		HASH_DEL(flowmap, hostnode);
		free(hostnode);
	}
	return;
}


int add_packet_to_network_flow(
		const u_int32_t sourceip,
		const u_int32_t destip,
		const u_int32_t sourceport,
		const u_int32_t destport,
		const u_char flag){

	int retval = 1;
	int addednew = 0; //This is used to signify that this connection is new

	struct host_node* hostnode = find_host_node_from_flowmap(sourceip);

	if(hostnode == NULL){
		printf("Adding new host");
				hostnode = makenewhostnode(sourceip);
		HASH_ADD_INT(flowmap,source_ip,hostnode);
	}


	struct connection* conn  =  find_connection_from_flowmap(
			hostnode, sourceip, destip, sourceport,destport);

	if( conn == NULL){
		conn = makenewconnection(sourceip,destip,sourceport, destport);
		HASH_ADD_INT(hostnode->connmap,key,conn);
		addednew = 1;
	}

	printf("Host and conn %p %p \n:", hostnode, conn);
	//Here both hostnode and conn should be not null
	assert(hostnode!= NULL && conn!=NULL);

	FLAG f = UNKNOWN;

	if(flag&TH_SYN){
		if(flag&TH_ACK){
			f = SYNACK;
			printf("XX:%s\n","SYNACK");
		}else{
			f = SYN;
			printf("XX:%s\n","SYN");
		}
	} else if(flag&TH_FIN){
		if(flag&TH_ACK){
			f = FINACK;
			printf("XX:%s\n","FINACK");
		}else{
			f = FIN;
			printf("XX:%s\n","FIN");
		}
	}else if (flag&TH_ACK){
		f = ACK;
		printf("XX:%s\n","ACK");
	} else if(flag&TH_RST) {
		f = RST;
		printf("XX:%s\n","RST");
	}else if (flag == 0){
		f = EMPTY;
	}else{//don't care for now
		f = UNKNOWN;
	}

	int flow_update = update_flow_with_packet(conn, f);

	if( flow_update == 0){ //Remove the connection
		retval = 0;
		if ( addednew == 1)
			remove_connection(hostnode, conn);
	}else{
		if(conn->state == 8 || conn->state == 0){
			remove_connection(hostnode,conn);
		}
	}


	return retval;
}


void print_host_node(struct host_node* hostnode){
	printf("\nIP :%s\n", convertfromintegertoIP(hostnode->source_ip));
	printf("Connmap :%p\n", hostnode->connmap);
}

void print_connection(struct connection* conn){
	printf("\nSource IP :%s\n", convertfromintegertoIP(conn->source_ip));
	printf("Dest IP :%s\n", convertfromintegertoIP(conn->dest_ip));
	printf("Source port :%d\n", conn->source_port);
	printf("Dest port :%d\n", conn->dest_port);
	printf("Conn active :%d\n", conn->is_conn_active);
	printf("Conn init :%d\n", conn->is_conn_init);
	printf("Conn tear :%d\n", conn->is_conn_teardown);
	printf("State :%d\n", conn->state);
}

