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
void convert_raw_to_udp_packet(eth_ip_udp_packet *pakiet_udp,unsigned char *buf_eth_udp,unsigned char size);

void print_arp(eth_arp_packet nagl_eth_arp);
void print_icmp(eth_ip_icmp_packet nagl_eth_ip_icmp);
void print_udp(eth_ip_udp_packet UDP);
void print_tcp(eth_ip_tcp_packet TCP);

unsigned int convertIntToBigEndian(unsigned int data);
unsigned short convertShortToBigEndian(unsigned short data);






#endif /* FUNKCJE_H_ */
