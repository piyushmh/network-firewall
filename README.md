README 

Environment

This code was developed on Ubuntu using gcc 4.7.3

Rules are present in a local file called rules.txt. Mutliple rules are applied according to priority. Source and destination mac interfaces are passed using command line arguments. The ARP values are hard coded currently and will be picked from a dynamic cache later. Packet are being
injected through pcap_inject library function. If the packet does not match any rules the default action is block.

Rules take the following format -

Pass SRCIP=60.50.40.30/24 SRCPORT=23 DSTIP=55.255.255.255 DSTPORT=34 PRIORITY=9


