################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/apply_rule.c \
../src/arptable.c \
../src/firewall_main.c \
../src/icmp_packet_handler.c \
../src/interactive_shell.c \
../src/network_flow.c \
../src/network_interface_card.c \
../src/packet_inject.c \
../src/packet_reader.c \
../src/string_util.c \
../src/tcp_packet_handler.c \
../src/temp.c 

OBJS += \
./src/apply_rule.o \
./src/arptable.o \
./src/firewall_main.o \
./src/icmp_packet_handler.o \
./src/interactive_shell.o \
./src/network_flow.o \
./src/network_interface_card.o \
./src/packet_inject.o \
./src/packet_reader.o \
./src/string_util.o \
./src/tcp_packet_handler.o \
./src/temp.o 

C_DEPS += \
./src/apply_rule.d \
./src/arptable.d \
./src/firewall_main.d \
./src/icmp_packet_handler.d \
./src/interactive_shell.d \
./src/network_flow.d \
./src/network_interface_card.d \
./src/packet_inject.d \
./src/packet_reader.d \
./src/string_util.d \
./src/tcp_packet_handler.d \
./src/temp.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


