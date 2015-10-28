/*
 * funkcje.c
 *
 *  Created on: Oct 28, 2015
 *      Author: daniel
 */
#include "funkcje.h"

void convert_raw_to_packet(eth_arp_packet *pakiet_arp,unsigned char *bufor_eth_arp,unsigned int eth_arp){
	memcpy(pakiet_arp,bufor_eth_arp,eth_arp);
}
