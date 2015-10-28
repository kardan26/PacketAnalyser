/*
 ============================================================================
 Name        : PacketAnalyzer.c
 Author      : Daniel Karwowski
 Version     :
 Copyright   : maked by kardan
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

#include "naglowki.h"
#include "funkcje.h"

int main(void) {
	//max eth = 6 + 6 +2 + 1500
	unsigned char bufor_eth_arp[1514] = {
										 0x30,0x85,0xa9,0x13,0x8e,0xaa,0x00,0x1a,0x92,0xb0,0x07,0x41,0x08,0x06,0x00,0x01,
										 0x08,0x00,0x06,0x04,0x00,0x02,0x00,0x1a,0x92,0xb0,0x07,0x41,0x0a,0x02,0x07,0x60,
										 0x30,0x85,0xa9,0x13,0x8e,0xaa,0x0a,0x02,0x07,0x79,0x00,0x00,0x00,0x00,0x00,0x00,
										 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};


	eth_arp_packet nagl_eth_arp;
	unsigned int arp_size = sizeof(eth_arp_packet);
	convert_raw_to_packet(&nagl_eth_arp,&bufor_eth_arp,arp_size);


	printf("**************************** ETHERNET / ARP *******************************************\n");
	printf("ETHERNET\n\n");
	printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n", nagl_eth_arp.eth2.dst_phy_address[0],nagl_eth_arp.eth2.dst_phy_address[1],nagl_eth_arp.eth2.dst_phy_address[2],nagl_eth_arp.eth2.dst_phy_address[3],nagl_eth_arp.eth2.dst_phy_address[4],nagl_eth_arp.eth2.dst_phy_address[5]);
	printf("MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n", nagl_eth_arp.eth2.src_phy_address[0],nagl_eth_arp.eth2.src_phy_address[1],nagl_eth_arp.eth2.src_phy_address[2],nagl_eth_arp.eth2.src_phy_address[3],nagl_eth_arp.eth2.src_phy_address[4],nagl_eth_arp.eth2.src_phy_address[5]);
	printf("Typ Ramki    - 0x%02x%02x\n",nagl_eth_arp.eth2.frame_type[0],nagl_eth_arp.eth2.frame_type[1]);

	printf("\nARP\n\n");
	printf("Typ protokolu warstwy fizycznej- 0x%02x%02x\n",nagl_eth_arp.arp.phy_address_space[0],nagl_eth_arp.arp.phy_address_space[1]);
	printf("Typ protokolu warstwy sieciowej- 0x%02x%02x\n", nagl_eth_arp.arp.pro_address_space[0],nagl_eth_arp.arp.pro_address_space[1]);
	printf("Długość adresu fizycznego- %d\n",nagl_eth_arp.arp.phy_address_length);
	printf("Długość adresu sieciowego- %d\n",nagl_eth_arp.arp.pro_address_length);
	printf("Opcode- 0x%02x%02x\n",nagl_eth_arp.arp.opcode[0],nagl_eth_arp.arp.opcode[1]);
	printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n", nagl_eth_arp.arp.destination_phy_addr[0],nagl_eth_arp.arp.destination_phy_addr[1],nagl_eth_arp.arp.destination_phy_addr[2],nagl_eth_arp.arp.destination_phy_addr[3],nagl_eth_arp.arp.destination_phy_addr[4],nagl_eth_arp.arp.destination_phy_addr[5]);
	printf("IP Odbiorcy - %d.%d.%d.%d\n",nagl_eth_arp.arp.destination_pro_addr[0],nagl_eth_arp.arp.destination_pro_addr[1],nagl_eth_arp.arp.destination_pro_addr[2],nagl_eth_arp.arp.destination_pro_addr[3]);
	printf("MAC Nadawcy - %02x:%02x:%02x:%02x:%02x:%02x\n", nagl_eth_arp.arp.source_phy_addr[0],nagl_eth_arp.arp.source_phy_addr[1],nagl_eth_arp.arp.source_phy_addr[2],nagl_eth_arp.arp.source_phy_addr[3],nagl_eth_arp.arp.source_phy_addr[4],nagl_eth_arp.arp.source_phy_addr[5]);
	printf("IP Nadawcy - %d.%d.%d.%d\n",nagl_eth_arp.arp.source_pro_addr[0],nagl_eth_arp.arp.source_pro_addr[1],nagl_eth_arp.arp.source_pro_addr[2],nagl_eth_arp.arp.source_pro_addr[3]);





	return EXIT_SUCCESS;
}
