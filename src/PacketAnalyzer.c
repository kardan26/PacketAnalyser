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

	unsigned char bufor_eth_ip_udp[1514]={
										0x00,0x09,0x0f,0xe7,0x86,0x23,0x30,0x85,0xa9,0x13,0x8e,0xaa,0x08,0x00,0x45,0x00,
										0x00,0x3e,0x0c,0x0a,0x00,0x00,0x80,0x11,0x00,0x00,0x0a,0x02,0x07,0x79,0x0a,0x01,
										0x00,0x01,0xfe,0x08,0x00,0x35,0x00,0x2a,0x1b,0xb8,0x18,0x30,0x01,0x00,0x00,0x01,
										0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x77,0x77,0x77,0x08,0x6d,0x73,0x66,0x74,0x6e,
										0x63,0x73,0x69,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01

	};

	unsigned char bufor_eth_ip_tcp[1514]={
										0x30,0x85,0xa9,0x13,0x8e,0xaa,0x00,0x09,0x0f,0xe7,0x86,0x23,0x08,0x00,0x45,0x00,
										0x00,0x6c,0x79,0xbf,0x40,0x00,0x31,0x06,0x34,0xea,0xd5,0xc7,0xb3,0xa0,0x0a,0x02,
										0x07,0x79,0x9c,0x4c,0xc5,0x4a,0x5a,0x01,0x51,0x73,0x38,0x5b,0x01,0xb2,0x50,0x18,
										0x00,0x1d,0xd8,0xe0,0x00,0x00,0xae,0xfb,0x85,0x90,0x37,0x8e,0xae,0xb5,0x03,0x4f,
										0xa6,0x2e,0x00,0x34,0xd8,0x4c,0x79,0x29,0x5e,0xa4,0x75,0x46,0xb9,0xa3,0x53,0x42,
										0xdb,0x11,0x77,0x71,0xc8,0xf9,0xab,0xb5,0x5e,0x84,0xe2,0x3e,0xb7,0x1c,0x4b,0x50,
										0x7f,0x6b,0x2c,0xa3,0xc1,0xaf,0x7d,0x50,0x65,0x66,0xa7,0xbd,0xb5,0x2e,0xb8,0x22,
										0x9f,0xd2,0x56,0x2c,0x7f,0xe8,0xcb,0xc9,0x4c,0x2d

	};


	eth_arp_packet nagl_eth_arp;
	unsigned int arp_size = sizeof(eth_arp_packet);
	convert_raw_to_arp_packet(&nagl_eth_arp,&bufor_eth_arp,arp_size);


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
	convert_raw_to_icmp_packet(&nagl_eth_ip_icmp,&bufor_eth_ip_icmp,icmp_size);

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
	printf("Flags - 0x%02x\n",nagl_eth_ip_icmp.ip4.flags.fields.flags);
	printf("Offset - %d\n",nagl_eth_ip_icmp.ip4.flags.fields.fragment_offset);
	printf("Czas życia - %d\n",nagl_eth_ip_icmp.ip4.time_to_live );
	printf("Protokół - %d\n",nagl_eth_ip_icmp.ip4.protocol );
	printf("Suma kontrolna nagłówka - 0x%02x\n",convertShortToBigEndian(nagl_eth_ip_icmp.ip4.header_checksum) );
	printf("IP Nadawcy - %d.%d.%d.%d\n",nagl_eth_ip_icmp.ip4.src_ip[0],nagl_eth_ip_icmp.ip4.src_ip[1],nagl_eth_ip_icmp.ip4.src_ip[2],nagl_eth_ip_icmp.ip4.src_ip[3]);
	printf("IP Odbiorcy - %d.%d.%d.%d\n",nagl_eth_ip_icmp.ip4.dst_ip[0],nagl_eth_ip_icmp.ip4.dst_ip[1],nagl_eth_ip_icmp.ip4.dst_ip[2],nagl_eth_ip_icmp.ip4.dst_ip[3]);

	printf("\n\nICMP\n\n");
	printf("Typ - %d\n",nagl_eth_ip_icmp.icmp.type);
	printf("Kod - %d\n",nagl_eth_ip_icmp.icmp.code);
	printf("Checksum - %02x\n",convertShortToBigEndian(nagl_eth_ip_icmp.icmp.checksum));
	printf("Identifier       - %d (0x%02x)\n",nagl_eth_ip_icmp.icmp.identifier,nagl_eth_ip_icmp.icmp.identifier);
	printf("Sequence Number  - %d (0x%02x)\n",nagl_eth_ip_icmp.icmp.seq_number,nagl_eth_ip_icmp.icmp.seq_number);


	eth_ip_udp_packet UDP;
	unsigned int udp_size = sizeof(eth_ip_udp_packet);
	memcpy(&UDP,&bufor_eth_ip_udp,udp_size);
	UDP.ip4.flags.bits = convertShortToBigEndian(UDP.ip4.flags.bits);


	printf("**************************** ETHERNET /IP/ UDP  *******************************************\n");
	printf("ETHERNET\n\n");

	printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n", UDP.eth2.dst_phy_address[0],UDP.eth2.dst_phy_address[1],UDP.eth2.dst_phy_address[2],UDP.eth2.dst_phy_address[3],UDP.eth2.dst_phy_address[4],UDP.eth2.dst_phy_address[5]);
	printf("MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n", UDP.eth2.src_phy_address[0],UDP.eth2.src_phy_address[1],UDP.eth2.src_phy_address[2],UDP.eth2.src_phy_address[3],UDP.eth2.src_phy_address[4],UDP.eth2.src_phy_address[5]);
	printf("Typ Ramki    - 0x%02x%02x\n",UDP.eth2.frame_type[0],UDP.eth2.frame_type[1]);

	printf("\n\nIP\n\n");
	printf("Wersja IP - %d\n",UDP.ip4.ver_leng.version);
	printf("IHL IP - %d\n",UDP.ip4.ver_leng.IHL);
	printf("Type Of Service - %d\n",UDP.ip4.type_of_service);
	printf("Type Length - %d\n",convertShortToBigEndian(UDP.ip4.total_length));
	printf("Identification - 0x%02x (%d)\n",convertShortToBigEndian(UDP.ip4.identification),convertShortToBigEndian(UDP.ip4.identification));
	printf("Flags - 0x%02x\n",UDP.ip4.flags.fields.flags);
	printf("Offset - %d\n",UDP.ip4.flags.fields.fragment_offset);
	printf("Czas życia - %d\n",UDP.ip4.time_to_live );
	printf("Protokół - %d\n",UDP.ip4.protocol );
	printf("Suma kontrolna nagłówka - 0x%02x\n",convertShortToBigEndian(UDP.ip4.header_checksum) );
	printf("IP Nadawcy - %d.%d.%d.%d\n",UDP.ip4.src_ip[0],UDP.ip4.src_ip[1],UDP.ip4.src_ip[2],UDP.ip4.src_ip[3]);
	printf("IP Odbiorcy - %d.%d.%d.%d\n",UDP.ip4.dst_ip[0],UDP.ip4.dst_ip[1],UDP.ip4.dst_ip[2],UDP.ip4.dst_ip[3]);

	printf("\n\nUDP\n\n");
	printf("Port Nadawcy   - %d\n", convertShortToBigEndian(UDP.udp.source_port));
	printf("Port Odbiorcy  - %d\n", convertShortToBigEndian(UDP.udp.destination_port));
	printf("Długość        - %d\n", convertShortToBigEndian(UDP.udp.length));
	printf("Suma kontrolna - 0x%02x",convertShortToBigEndian(UDP.udp.checksum));


	eth_ip_tcp_packet TCP;
	unsigned int tcp_size = sizeof(eth_ip_tcp_packet);
//	memcpy(&TCP,&bufor_eth_ip_tcp,tcp_size);
//	TCP.ip4.flags.bits = convertShortToBigEndian(TCP.ip4.flags.bits);
	convert_raw_to_tcp_packet(&TCP,&bufor_eth_ip_tcp,tcp_size);



	printf("\n\n**************************** ETHERNET /IP/ TCP  *******************************************\n");
	printf("ETHERNET\n\n");

	printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n", TCP.eth2.dst_phy_address[0],TCP.eth2.dst_phy_address[1],TCP.eth2.dst_phy_address[2],TCP.eth2.dst_phy_address[3],TCP.eth2.dst_phy_address[4],TCP.eth2.dst_phy_address[5]);
	printf("MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n", TCP.eth2.src_phy_address[0],TCP.eth2.src_phy_address[1],TCP.eth2.src_phy_address[2],TCP.eth2.src_phy_address[3],TCP.eth2.src_phy_address[4],TCP.eth2.src_phy_address[5]);
	printf("Typ Ramki    - 0x%02x%02x\n",TCP.eth2.frame_type[0],TCP.eth2.frame_type[1]);

	printf("\n\nIP\n\n");
	printf("Wersja IP - %d\n",TCP.ip4.ver_leng.version);
	printf("IHL IP - %d\n",TCP.ip4.ver_leng.IHL);
	printf("Type Of Service - %d\n",TCP.ip4.type_of_service);
	printf("Type Length - %d\n",convertShortToBigEndian(TCP.ip4.total_length));
	printf("Identification - 0x%02x (%d)\n",convertShortToBigEndian(TCP.ip4.identification),convertShortToBigEndian(TCP.ip4.identification));
	printf("Flags - 0x%02x\n",TCP.ip4.flags.fields.flags);
	printf("Offset - %d\n",TCP.ip4.flags.fields.fragment_offset);
	printf("Czas życia - %d\n",TCP.ip4.time_to_live );
	printf("Protokół - %d\n",TCP.ip4.protocol );
	printf("Suma kontrolna nagłówka - 0x%02x\n",convertShortToBigEndian(TCP.ip4.header_checksum) );
	printf("IP Nadawcy - %d.%d.%d.%d\n",TCP.ip4.src_ip[0],TCP.ip4.src_ip[1],TCP.ip4.src_ip[2],TCP.ip4.src_ip[3]);
	printf("IP Odbiorcy - %d.%d.%d.%d\n",TCP.ip4.dst_ip[0],TCP.ip4.dst_ip[1],TCP.ip4.dst_ip[2],TCP.ip4.dst_ip[3]);

	printf("\n\nTCP\n\n");
	printf("Port Nadawcy   - %d\n", convertShortToBigEndian(TCP.tcp.source_port));
	printf("Port Odbiorcy  - %d\n", convertShortToBigEndian(TCP.tcp.destination_port));
	printf("Sequence Number- 0x%02x\n",TCP.tcp.sequence_number,TCP.tcp.sequence_number);
	printf("ACK            - 0x%02x\n",TCP.tcp.ack,TCP.tcp.ack);
	printf("Data Offset    - 0x%02x\n",TCP.tcp.flags.fields.data_offset);
	printf("Reserved       - 0x%02x\n",TCP.tcp.flags.fields.reserved);
	printf("Control Bits   - 0x%02x\n",TCP.tcp.flags.fields.control_bits);
	printf("Window     - 0x%04x\n",TCP.tcp.window);
	printf("Checksum   - 0x%02x\n",TCP.tcp.checksum);
	printf("Urgent Pointer - 0x%04x\n",TCP.tcp.urgent_pointer);







	return EXIT_SUCCESS;
}
