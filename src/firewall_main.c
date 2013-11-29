#include <libnet.h>

#include "firewall_main.h"
//#include "network_interface_card.h"
#include "apply_rule.h"
#include <stdio.h>
#include "string_util.h"
int main(int argc, char** argv){

    initialize_rules(); //read rules of files and initialize system
	initialize_start_interfaces();
    return(0);
}
