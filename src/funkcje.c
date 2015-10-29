/*
 * funkcje.c
 *
 *  Created on: Oct 28, 2015
 *      Author: daniel
 */
#include "funkcje.h"

void convert_raw_to_arp_packet(eth_arp_packet *pakiet_arp,unsigned char *bufor_eth_arp,unsigned int eth_arp){
	memcpy(pakiet_arp,bufor_eth_arp,eth_arp);
}

void convert_raw_to_icmp_packet(eth_ip_icmp_packet *pakiet_icmp,unsigned char *bufor_eth_icmp,unsigned int size){
	memcpy(pakiet_icmp,bufor_eth_icmp,size);
	pakiet_icmp->ip4.flags.bits = convertShortToBigEndian(pakiet_icmp->ip4.flags.bits);

	pakiet_icmp->icmp.checksum = convertShortToBigEndian(pakiet_icmp->icmp.checksum);
	pakiet_icmp->icmp.identifier = convertShortToBigEndian(pakiet_icmp->icmp.identifier);
	pakiet_icmp->icmp.seq_number = convertShortToBigEndian(pakiet_icmp->icmp.seq_number);
}

void convert_raw_to_tcp_packet(eth_ip_tcp_packet *pakiet_tcp,unsigned char *bufor_eth_tcp,unsigned int size){
	memcpy(pakiet_tcp,bufor_eth_tcp,size);
	pakiet_tcp->ip4.flags.bits = convertShortToBigEndian(pakiet_tcp->ip4.flags.bits);
	memcpy(&pakiet_tcp->tcp,bufor_eth_tcp+34,sizeof(tcp_frame));
	pakiet_tcp->tcp.sequence_number = convertIntToBigEndian(pakiet_tcp->tcp.sequence_number );
	pakiet_tcp->tcp.ack = convertIntToBigEndian(pakiet_tcp->tcp.ack);
	pakiet_tcp->tcp.flags.bits = convertShortToBigEndian(pakiet_tcp->tcp.flags.bits);
	pakiet_tcp->tcp.window =  convertShortToBigEndian(pakiet_tcp->tcp.window);
	pakiet_tcp->tcp.checksum = convertShortToBigEndian(pakiet_tcp->tcp.checksum);
	pakiet_tcp->tcp.urgent_pointer = convertShortToBigEndian(pakiet_tcp->tcp.urgent_pointer);
}

unsigned short convertShortToBigEndian(unsigned short data){

	short num = ((data & 0xff00)>>8) | ((data & 0x00ff)<<8);
	return num;

}

unsigned int convertIntToBigEndian(unsigned int data){
	int a0 = (data & 0x000000ff) << 24;
	int a1 = (data & 0x0000ff00) <<8;
	int a2 = (data & 0x00ff0000) >>8;
	int a3 = (data & 0xff000000) >>24;

	unsigned int num = a0 | a1 | a2 | a3;
	return num;

}
