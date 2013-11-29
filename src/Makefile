all: Networkfirewall
.PHONY: all

obj/:
	mkdir -p obj

obj/%.o: %.c %.h obj/
	gcc -g -Wall -c $< -o $@

Networkfirewall: obj/arptable.o obj/packet_reader.o obj/apply_rule.o obj/packet_inject.o obj/network_interface.o obj/string_util.o
	gcc -g firewall_main.c firewall_main.h -o $@ obj/network_interface.o obj/string_util.o -lpcap

clean:
	rm -f obj/*.o Networkfirewall
	rmdir -p obj
.PHONY: clean
