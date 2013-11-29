#include <libnet.h>

#include "firewall_main.h"
//#include "network_interface_card.h"
#include "apply_rule.h"
#include <stdio.h>
#include "string_util.h"
int main(int argc, char** argv){
 	/*
    int c;
    char *sourcedev = NULL;
    char *destdev = NULL;
    while((c = getopt(argc, argv, "s:d:")) != EOF){
    	switch (c) {
            case 's' :
                sourcedev = optarg;
                break;
            case 'd' :
                destdev = optarg;
                break;
            default:
                printf("%s\n", "Enter correct arguments");
                exit(3);
        }
    }

    if(destdev == NULL){
        printf("%s\n", "Enter correct arguments1");
        exit(3);
    }

    if(sourcedev == NULL){
        printf("%s\n", "Enter correct arguments2");
        exit(3);
    }
	*/
	//printf("Ass");
	//pp("DD\n");

    initialize_rules(); //read rules of files and initialize system
    //initialize_interfaces();
    //read_packets(sourcedev, destdev);
    return(0);
}
