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
	unsigned char bufor_eth_ip_icmp[1514]={
										0x00,0x09,0x0f,0xe7,0x86,0x23,0x30,0x85,0xa9,0x13,0x8e,0xaa,0x08,0x00,0x45,0x00,
										0x00,0x3c,0x65,0xb2,0x00,0x00,0xff,0x01,0x00,0x00,0x0a,0x02,0x07,0x79,0xac,0x14,
										0x32,0x32,0x08,0x00,0x2b,0x8a,0x3c,0x3c,0xdf,0x47,0x3c,0x3c,0xd7,0x47,0xfa,0xf0,
										0x2f,0xf7,0x09,0x72,0x86,0x48,0xb9,0xb4,0xe0,0xad,0x25,0x38,0xad,0x59,0x07,0x56,
										0xa7,0x0b,0x82,0x2f,0xbf,0x64,0x0a,0x9a,0x73,0x46

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


	eth_ip_icmp_packet nagl_eth_ip_icmp;
	unsigned int icmp_size = sizeof(eth_ip_icmp_packet);
	memcpy(&nagl_eth_ip_icmp,&bufor_eth_ip_icmp,icmp_size);

	printf("**************************** ETHERNET /IP/ ICMP  *******************************************\n");
	printf("ETHERNET\n\n");
	printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n", nagl_eth_ip_icmp.eth2.dst_phy_address[0],nagl_eth_ip_icmp.eth2.dst_phy_address[1],nagl_eth_ip_icmp.eth2.dst_phy_address[2],nagl_eth_ip_icmp.eth2.dst_phy_address[3],nagl_eth_ip_icmp.eth2.dst_phy_address[4],nagl_eth_ip_icmp.eth2.dst_phy_address[5]);
	printf("MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n", nagl_eth_ip_icmp.eth2.src_phy_address[0],nagl_eth_ip_icmp.eth2.src_phy_address[1],nagl_eth_ip_icmp.eth2.src_phy_address[2],nagl_eth_ip_icmp.eth2.src_phy_address[3],nagl_eth_ip_icmp.eth2.src_phy_address[4],nagl_eth_ip_icmp.eth2.src_phy_address[5]);
	printf("Typ Ramki    - 0x%02x%02x\n",nagl_eth_ip_icmp.eth2.frame_type[0],nagl_eth_ip_icmp.eth2.frame_type[1]);
	printf("\n\nIP\n\n");
	printf("Wersja IP - %d\n",nagl_eth_ip_icmp.ip4.ver_leng.version);
	printf("IHL IP - %d\n",nagl_eth_ip_icmp.ip4.ver_leng.IHL);
	printf("Type Of Service - %d\n",nagl_eth_ip_icmp.ip4.type_of_service);
	printf("Type Length - %d\n",convertShortToBigEndian(nagl_eth_ip_icmp.ip4.total_length));
	printf("Identification - 0x%02x (%d)\n",convertShortToBigEndian(nagl_eth_ip_icmp.ip4.identification),convertShortToBigEndian(nagl_eth_ip_icmp.ip4.identification));
	printf("Flags - 0x%02x\n",nagl_eth_ip_icmp.ip4.flags.flags);
	printf("Offset - %d\n",nagl_eth_ip_icmp.ip4.flags.fragment_offset);
	printf("Czas życia - %d\n",nagl_eth_ip_icmp.ip4.time_to_live );
	printf("Protokół - %d\n",nagl_eth_ip_icmp.ip4.protocol );
	printf("Suma kontrolna nagłówka - 0x%02x\n",convertShortToBigEndian(nagl_eth_ip_icmp.ip4.header_checksum) );
	printf("IP Nadawcy - %d.%d.%d.%d\n",nagl_eth_ip_icmp.ip4.src_ip[0],nagl_eth_ip_icmp.ip4.src_ip[1],nagl_eth_ip_icmp.ip4.src_ip[2],nagl_eth_ip_icmp.ip4.src_ip[3]);
	printf("IP Odbiorcy - %d.%d.%d.%d\n",nagl_eth_ip_icmp.ip4.dst_ip[0],nagl_eth_ip_icmp.ip4.dst_ip[1],nagl_eth_ip_icmp.ip4.dst_ip[2],nagl_eth_ip_icmp.ip4.dst_ip[3]);

	printf("\n\nICMP\n\n");
	printf("Typ - %d\n",nagl_eth_ip_icmp.icmp.type);
	printf("Kod - %d\n",nagl_eth_ip_icmp.icmp.code);
	printf("Checksum - %02x\n",convertShortToBigEndian(nagl_eth_ip_icmp.icmp.checksum));

	return EXIT_SUCCESS;
}
