/*
 * tcp_packet_handler.c
 *
 *  Created on: 09-Dec-2013
 *      Author: piyush
 */


#include "tcp_packet_handler.h"


void handle_tcp_packet(){
	/*
	if (pthread_rwlock_rdlock(&(flowmap_lock)) != 0){
				pp("Can't acquire read lock on flowmap, check what happened!!");
				return;
			}

			res = is_packet_part_of_open_connection(
					sourceip, destip, sourceport, destport);

			pthread_rwlock_unlock(&(flowmap_lock));

			if( res == 0){
				int rule_apply = traverse_rule_matrix(
						protocol, sourceip, destip, sourceport, destport,
						sourcemac, destmac);
				if( rule_apply == 1){
					update_flow = 1;
				}
			}else{
				update_flow = 1;
			}

			if( update_flow == 1){
				if (pthread_rwlock_wrlock(&(flowmap_lock)) != 0){
					pp("Can't acquire write lock on flowmap, check what happened!!");
					return;
				}
				int result = add_packet_to_network_flow(
						sourceip,destip, sourceport, destport, tcp->th_flags);

				pthread_rwlock_unlock(&(flowmap_lock));

				if( result ==1)
					block =0;
			}
			*/
}
