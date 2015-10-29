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

unsigned short convertShortToBigEndian(unsigned short data){

	short num = ((data & 0xff00)>>8) | ((data & 0x00ff)<<8);
	return num;

}
