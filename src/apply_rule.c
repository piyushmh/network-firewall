/*
 * apply_rule.c
 *
 *  Created on: 05-Nov-2013
 *      Author: piyush
 */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "apply_rule.h"
#include "firewall_rules.h"
#include "string_util.h"

#define MINPRIORITY 9

//Change this later to one list per interface
struct firewall_rule* rules[] = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
int next_rule_id;
pthread_rwlock_t rulelist_lock;


char rule_file_path[] = "/home/piyush/dcn/project_final/NetworkFirewall/src/rules.txt";

void add_rule_to_list(struct firewall_rule **head, struct firewall_rule* rule ){
	if(*head == NULL){
		*head = rule;
		return;
	}
	rule->next = *head;
	(*head)->prev = rule;
	*head = rule;
	return;
}

struct firewall_rule* makerulenode(){

	struct firewall_rule* rulenode =
			(struct firewall_rule*)malloc(sizeof(struct firewall_rule));
	rulenode->id = next_rule_id;
	next_rule_id +=1; //Increment the rule_id to next value
	rulenode->protocol = ALL;
	rulenode->is_active = 1;
	rulenode->sourceip  = 0;
	rulenode->sourceipmask =0;
	rulenode->destip = 0;
	rulenode->destipmask = 0;
	struct portrange range;
	range.start = 0; range.end = (1<<16) - 1; //MAX PORT RANGE
	rulenode->sourceportrange = range;
	rulenode->destportrange = range;
	rulenode->priority = MINPRIORITY;
	rulenode->next = NULL;
	rulenode->prev = NULL;
	rulenode->action = BLOCK;
	return rulenode;
}

/*
 * Make rule from the rule string
 * This method parses the rule string into its
 * corresponding elements. Null value means that
 * the rule string was malformed
 */
struct firewall_rule* makerule(char* rulestring){

	struct firewall_rule* rule =  makerulenode();
	rule->next = NULL;
	rule->prev = NULL;
	char *saveptr;
	char *token;
	for( ;; rulestring = NULL){
		token  = strtok_r(rulestring," ", &saveptr);
		if(token == NULL)
			break;

		if( strcmp(token,"Pass")==0){
			rule->action = PASS;
			continue;
		}
		if(strcmp(token,"Block")==0){
			rule->action = BLOCK;
			continue;
		}

		char *str2 = token;
		char *saveptr2;
		char *subtoken1 = strtok_r(str2, "=", &saveptr2);
		if(subtoken1 == NULL){
			rule = NULL;
			break;
		}
		char *subtoken2 = strtok_r(NULL, "=", &saveptr2);
		if( subtoken2 == NULL){
			rule = NULL;
			break;
		}

		if(strcmp(subtoken1, "PROTOCOL") == 0){
			if(strcmp(subtoken2,"ANY")){
				if(strcmp(subtoken2, "TCP")==0)
					rule->protocol = TCP;
				else if(strcmp(subtoken2, "UDP")==0)
					rule->protocol = UDP;
				else if(strcmp(subtoken2, "ICMP")==0)
					rule->protocol = ICMP;
				else{
					//Add later
				}

			}
		}
		else if(strcmp(subtoken1,"SRCIP")==0){

			if(strcmp(subtoken2,"ANY")){
				char *saveptr3;
				char *temp = subtoken2;
				char *subtoken3 = strtok_r(temp,"/",&saveptr3);
				char *subtoken4 = strtok_r(NULL,"/",&saveptr3);
				if(subtoken3 == NULL){//this should not we should have a valid IP
					rule = NULL;
					break;
				}
				struct in_addr sip;
				inet_aton(subtoken3, &sip);
				rule->sourceip = sip.s_addr;

				if(subtoken4 == NULL){
					rule->sourceipmask = 32;
				}else{
					rule->sourceipmask = atoi(subtoken4);
				}
			}

		}else if(strcmp(subtoken1,"SRCPORT")==0){
			if(strcmp(subtoken2,"ANY")){
				char *saveptr3;
				char *temp = subtoken2;
				char *subtoken3 = strtok_r(temp,"-",&saveptr3);
				char *subtoken4 = strtok_r(NULL,"-",&saveptr3);
				if(subtoken3 == NULL){
					rule = NULL;
					break;
				}
				rule->sourceportrange.start = atoi(subtoken3);
				if(subtoken4 == NULL){
					rule->sourceportrange.end = rule->sourceportrange.start;
				}else{
					rule->sourceportrange.start = atoi(subtoken4);
				}
			}
		}
		else if(strcmp(subtoken1,"DSTIP")==0){

			if(strcmp(subtoken2,"ANY")){
				char *saveptr3;
				char *temp = subtoken2;
				char *subtoken3 = strtok_r(temp,"/",&saveptr3);
				char *subtoken4 = strtok_r(NULL,"/",&saveptr3);
				if(subtoken3 == NULL){//this should not we should have a valid IP
					rule = NULL;
					break;
				}
				struct in_addr sip;
				inet_aton(subtoken3, &sip);
				rule->destip = sip.s_addr;
				if(subtoken4 == NULL){
					rule->destipmask = 32;
				}else{
					rule->destipmask = atoi(subtoken4);
				}
			}
		}
		else if(strcmp(subtoken1,"DSTPORT")==0){
			if(strcmp(subtoken2,"ANY")){
				char *saveptr3;
				char *temp = subtoken2;
				char *subtoken3 = strtok_r(temp,"-",&saveptr3);
				char *subtoken4 = strtok_r(NULL,"-",&saveptr3);
				if(subtoken3 == NULL){
					rule = NULL;
					break;
				}
				rule->destportrange.start = atoi(subtoken3);
				if(subtoken4 == NULL){
					rule->destportrange.end = rule->destportrange.start;
				}else{
					rule->destportrange.start = atoi(subtoken4);
				}
			}
		}
		else if(strcmp(subtoken1,"PRIORITY")==0){
			rule->priority = atoi(subtoken2);
			if(rule->priority > MINPRIORITY){
				rule = NULL;
				break;
			}
		}
		else {
			rule = NULL;
			break;
		}
	}

	return rule;
}

void print_rule(struct firewall_rule* rule){
	if( rule->is_active == 0)
		return;
	char proto[16];
	if(rule->protocol==TCP) strcpy(proto,"TCP");
	else if (rule->protocol==UDP) strcpy(proto,"UDP");
	else if (rule->protocol==ICMP) strcpy(proto,"ICMP");
	else strcpy(proto,"ALL");

	printf("\nID  :%d  ", rule->id);
	printf("Active :%d  ", rule->is_active);
	printf("Proto :%s  ", proto);
	printf("SRCIP :%s  ", convertfromintegertoIP(rule->sourceip));
	printf("SRCMASK :%d  ", rule->sourceipmask);
	printf("DSTIP :%s  ", convertfromintegertoIP(rule->destip));
	printf("DSTMASK :%d  ", rule->destipmask);
	printf("SRCPORT :%d-%d  ", rule->sourceportrange.start, rule->sourceportrange.end);
	printf("DSTPORT :%d-%d  ", rule->destportrange.start, rule->destportrange.end);
	printf("Action :%d  ", rule->action);
	printf("Priority :%d  ", rule->priority);
	fflush(stdout);
}


void traverseLL(struct firewall_rule* head){
	if(head==NULL){
		//printf("No rules\n");
		return;
	}
	while(head!=NULL){
		print_rule(head);
		head = head->next;
	}
	//printf("\n");
}

void traverse(){
	int i;
	for(i=0;i<=MINPRIORITY;i++){
		printf("Rules of priority %d", i);
		struct firewall_rule* head = rules[i];
		traverseLL(head);
		printf("\n");
	}
}

void initialize_rules(){


	if (pthread_rwlock_init(&(rulelist_lock),NULL) != 0){
		pp("Cannot initialize read write lock for rule list, exiting thread");
		exit(1);
	}
	FILE *rulefile = NULL;
	rulefile = fopen(rule_file_path, "r");
	next_rule_id = 0; //Initializing rule id to 0
	if(rulefile == NULL){
		printf("Could open the rules file, no rules would be applied, skipping");
		return;
	}

	char* rule = (char*) malloc(512);
	char* rule_par = (char*) malloc(512);
	size_t len = 512;
	size_t read;
	while ((read = getline(&rule, &len, rulefile)) != -1) {
		rule = strstrip(rule);
		strcpy(rule_par, rule);
		struct firewall_rule* x = makerule(rule_par);
		if(x!=NULL){
			add_rule_to_list(&rules[x->priority],x);
			printf("Applied rule :%s\n", rule);
		}else{
			printf("Rule malformed, skipping :%s\n", rule);
		}
	}
	//traverse();
}

struct firewall_rule** findrulehead(u_int32_t sourceip){
	return rules;
}

//Just doing a single match now
int match_single_rule(struct firewall_rule* rulenode,
		struct firewall_rule packetdec){

	//print_rule(rulenode);
	int retval = 0;
	if ( rulenode->protocol == ALL || rulenode->protocol==packetdec.protocol){
		if( match_ip_to_subnet_mask_integers(
				packetdec.sourceip, rulenode->sourceipmask, rulenode->sourceip)){
			if( match_ip_to_subnet_mask_integers(
					packetdec.destip, rulenode->destipmask, rulenode->destip)){
				if( packetdec.sourceportrange.start >= rulenode->sourceportrange.start
						&& packetdec.sourceportrange.start <= rulenode->sourceportrange.end){
					if( packetdec.destportrange.start >= rulenode->destportrange.start
							&& packetdec.destportrange.start <= rulenode->destportrange.end){
						//print_rule(rulenode);
						retval = 1;
					}
				}
			}
		}
	}
	return retval;
}

struct firewall_rule* traverse_rule_chain(struct firewall_rule* head,
		struct firewall_rule packetdes){

	if(head==NULL){
		return NULL;
	}
	while(head!=NULL){
		if(head->is_active){
			if(match_single_rule(head, packetdes)){
				break;
			}
		}
		head = head->next;
	}

	return head;
}

int checkIfSameSubnet(u_int32_t sourceip, struct network_interface sourcedevice){
	return 0; //Add implementation later
}


int traverse_rule_matrix( enum PROTOCOL proto, u_int32_t sourceip,
		u_int32_t destip, u_short sourceport, u_short destport,
		u_char *sourcemac, u_char *destmac){

	if (pthread_rwlock_rdlock(&(rulelist_lock)) != 0){
		pp("Can't acquire read lock on rule list, check what happened!!");
		return 0;
	}

	int returncode = 0; //default action is  block everything

	struct firewall_rule packetdes;
	struct portrange port;

	packetdes.sourceip = sourceip;
	port.start =sourceport; port.end = sourceport;
	packetdes.sourceportrange = port;
	packetdes.destip = destip;
	port.start =destport; port.end = destport;
	packetdes.destportrange = port;
	memcpy(packetdes.sourcemacaddr,sourcemac, ETHER_ADDR_LEN);
	memcpy(packetdes.destmacaddr,destmac, ETHER_ADDR_LEN);
	packetdes.sourceipmask = 0;
	packetdes.destipmask = 0;
	packetdes.protocol = proto;

	struct firewall_rule** rulehead = findrulehead(sourceip);

	int i;
	struct firewall_rule* matched_rule = NULL;
	for(i=0; i<=MINPRIORITY;i++){
		matched_rule = traverse_rule_chain(rulehead[i], packetdes);
		if(matched_rule!=NULL){
			break;
		}
	}

	if(matched_rule != NULL){//we found matching rule
		if(matched_rule->action == BLOCK)
			returncode = 0;
		else if(matched_rule->action == PASS)
			returncode = 1;
	}else{
		//no match means block which the default value of returncode
	}
	pthread_rwlock_unlock(&(rulelist_lock));
	return returncode;
}

int add_rule_to_list_external(char* rule){
	if (pthread_rwlock_wrlock(&(rulelist_lock)) != 0){
		pp("Add rule:Can't acquire write lock on rule list, check what happened!!");
		return 0;
	}
	int retvalue;
	char* rule_param = (char*)malloc(512);
	strcpy(rule_param, rule);
	struct firewall_rule* ruleformed = makerule(rule_param);
	if( ruleformed == NULL){
		retvalue = 0;
	}else{
		retvalue = 1;
		if( ruleformed->priority >=0 && ruleformed->priority <= MINPRIORITY)
			add_rule_to_list(&rules[ruleformed->priority],ruleformed);
		else
			retvalue = 0;
	}
	pthread_rwlock_unlock(&(rulelist_lock));
	return retvalue;
}


int _mark_rule_inactive_ll(struct firewall_rule* head, const int ruleid){
	if (pthread_rwlock_wrlock(&(rulelist_lock)) != 0){
		pp("Mark rule inactive:Can't acquire write lock on rule list, check what happened!!");
		return 0;
	}
	int retval = 0;
	while(head!=NULL){
		if(head->id == ruleid){
			head->is_active = 0;
			retval = 1;
		}
		head = head->next;
	}
	pthread_rwlock_unlock(&(rulelist_lock));
	return retval;
}

int mark_rule_as_inactive(int ruleid){
	int retval = 0;
	int i;
	for(i=0; i<=MINPRIORITY;i++){
		int val = _mark_rule_inactive_ll(rules[i], ruleid);
		if(val){
			retval = 1;
			break;
		}
	}
	return retval;
}

void print_all_rules(){
	traverse();
}
