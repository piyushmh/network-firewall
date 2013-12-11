/*
 * interactive_shell.c
 *
 *  Created on: 08-Dec-2013
 *      Author: piyush
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "interactive_shell.h"
#include "apply_rule.h"
#include "string_util.h"

void start_shell(){

	printf("\nInteractive firewall rule shell, press H for help.\n");
	char* command = (char*)malloc(10);
	size_t commandlen = 512;
	while(1){
		printf("Firewall>");
		getline(&command, &commandlen,stdin);
		command = strstrip(command);
		if( strcmp(command,"H")==0){
			printf("Press A, and then add a rule in the following format : ");
			printf("Pass|Block PROTOCOL=(TCP/UDP/ICMP) SRCIP=a.b.c.d/m SRCPORT=p-q DSTIP=w.x.y.z/n DSTPORT=r-s PRIORITY=p\n");
			printf("Press D, and then press rule id to delete\n");
			printf("Press P to print all rules\n");
			printf("Press E to exit the shell\n");
		}else if(strcmp(command,"A")==0){

			printf("Enter the rule :");
			char* rule = (char*) malloc(512);
			size_t len = 512;
			getline(&rule, &len, stdin);
			int result = add_rule_to_list_external(rule);
			if( result ==1){
				printf("Yay rule applied.\n");
			}else{
				printf("Malformed rule, skipping\n");
			}
			free(rule);
		}else if( strcmp(command,"D")==0){
			int ruleid = -1;
			printf("Please enter a valid rule id to delete :");
			scanf("%d", &ruleid);
			getchar();
			int res = mark_rule_as_inactive(ruleid);
			if( res ==1){
				printf("Rule deleted.\n");
			}else{
				printf("Rule id not found, skipping\n");
			}
		}else if( strcmp(command,"P")==0){
			print_all_rules();
		}else if( strcmp(command,"E")==0){
			printf("Good bye\n");
			break;
		}else{
			printf("I have no idea what you're saying but the answer is 42\n");
		}
	}
	return;
}

