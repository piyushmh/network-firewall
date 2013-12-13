README 

Environment

This code was developed on Ubuntu using gcc 4.7.3 using Eclipse IDE 

Build    1) cd Debug
         2) make clean; make
Run      sudo ./NetworkFirewall
           

NetworkFirewall is a software which can be used to apply pass/block packets between virtually isolated networks. List of interfaces can be supplied in a files called interfaces.txt along with their hardware mac addresses. A separate threads listens to each interface present in this file. pthread reader writer locks for used for synchronization on internal data structures. Rules are present in a local file called rules.txt. Packets are injected through pcap_inject library function. Mutliple rules are applied according to priority. If the packet does not match any rules the default action is block. For getting ARP entry for a local LAN host, arping is done, and the value is stored in a cache with a 60 sec timeout. Once a connection has been formed between 2 hosts, rules are not applied for that flow. Flows are maintained in hash structures. Hash structures basically maintain a simplefied TCP state machine. UTHash library is being used for hashing. Rules are applied on bidirectional traffic and hence any communication must have an allow rules both ways. A brief documentation is contained in NetworkFirewall.pdf. 

Once the firewall is running, rules are be changed dynamically using a interactive shell. It only understands a few commands. Press H for help and command syntax.

Rules take the following format ( Highest priority is 0). Protocols supportes are ICMP|TCP|UDP. Flow is only maintained for TCP and not for ICMP or UDP.

Pass PROTOCOL=protocolSRCIP=60.50.40.30/24 SRCPORT=23 DSTIP=55.255.255.255 DSTPORT=34 PRIORITY=9


