#include <libnet.h>

#include "firewall_main.h"
//#include "network_interface_card.h"
#include "apply_rule.h"
#include <stdio.h>
#include <stdlib.h>
#include "string_util.h"
#include "network_flow.h"

int main(int argc, char** argv){

	if(argc == 2){
		if ( strcmp(argv[1], "--usage") == 0 ){
			printf("Network Firewall\n");
			printf("NetworkFirewall --usage\t\tUsage\n");
			printf("NetworkFirewall pcap_file_path  Pass pcap file to replay pcap traffic\n");
			printf("NetworkFirewall\t\t\tNo arguments to run firewall\n");
			exit(0);
		}
		else{
			initialize_network_flow();
			initialize_rules();
			handle_pcap_file(argv[1]);
		}
	}
	else if(argc != 2){
		initialize_network_flow();
    	initialize_rules(); //read rules of files and initialize system
		initialize_start_interfaces();
	}


    return(0);
}
