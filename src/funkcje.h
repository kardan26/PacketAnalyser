/*
 * funkcje.h
 *
 *  Created on: Oct 28, 2015
 *      Author: daniel
 */

#ifndef FUNKCJE_H_
#define FUNKCJE_H_

#include "naglowki.h"
#include <stdio.h>
#include <string.h>

void convert_raw_to_arp_packet(eth_arp_packet *pakiet_arp,unsigned char *bufor_eth_arp,unsigned int eth_arp);
void convert_raw_to_icmp_packet(eth_ip_icmp_packet *pakiet_arp,unsigned char *bufor_eth_icmp,unsigned int size);
void convert_raw_to_tcp_packet(eth_ip_tcp_packet *pakiet_tcp,unsigned char *bufor_eth_tcp,unsigned int size);

unsigned int convertIntToBigEndian(unsigned int data);
unsigned short convertShortToBigEndian(unsigned short data);

#endif /* FUNKCJE_H_ */
