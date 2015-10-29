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
	pakiet_icmp->ip4.total_length = convertShortToBigEndian(pakiet_icmp->ip4.total_length);
	pakiet_icmp->ip4.identification = convertShortToBigEndian(pakiet_icmp->ip4.identification);
	pakiet_icmp->ip4.header_checksum = convertShortToBigEndian(pakiet_icmp->ip4.header_checksum);
	pakiet_icmp->icmp.checksum = convertShortToBigEndian(pakiet_icmp->icmp.checksum);

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
	pakiet_tcp->tcp.options_padding.bits = convertIntToBigEndian(pakiet_tcp->tcp.options_padding.bits);

	pakiet_tcp->ip4.total_length = convertShortToBigEndian(pakiet_tcp->ip4.total_length);
	pakiet_tcp->ip4.identification = convertShortToBigEndian(pakiet_tcp->ip4.identification);
	pakiet_tcp->ip4.header_checksum = convertShortToBigEndian(pakiet_tcp->ip4.header_checksum);

	pakiet_tcp->tcp.source_port = convertShortToBigEndian(pakiet_tcp->tcp.source_port);
	pakiet_tcp->tcp.destination_port = convertShortToBigEndian(pakiet_tcp->tcp.destination_port);
}

void convert_raw_to_udp_packet(eth_ip_udp_packet *pakiet_udp,unsigned char *buf_eth_udp,unsigned char size){
	memcpy(pakiet_udp,buf_eth_udp,size);
	pakiet_udp->ip4.flags.bits = convertShortToBigEndian(pakiet_udp->ip4.flags.bits);
	pakiet_udp->ip4.total_length = convertShortToBigEndian(pakiet_udp->ip4.total_length);
	pakiet_udp->ip4.identification = convertShortToBigEndian(pakiet_udp->ip4.identification);
	pakiet_udp->ip4.header_checksum = convertShortToBigEndian(pakiet_udp->ip4.header_checksum);

	pakiet_udp->udp.source_port = convertShortToBigEndian(pakiet_udp->udp.source_port);
	pakiet_udp->udp.destination_port = convertShortToBigEndian(pakiet_udp->udp.destination_port);
	pakiet_udp->udp.length = convertShortToBigEndian(pakiet_udp->udp.length);
	pakiet_udp->udp.checksum = convertShortToBigEndian(pakiet_udp->udp.checksum);
}
void print_arp(eth_arp_packet nagl_eth_arp){

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

}
void print_udp(eth_ip_udp_packet UDP){
	printf("**************************** ETHERNET /IP/ UDP  *******************************************\n");
		printf("ETHERNET\n\n");

		printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n", UDP.eth2.dst_phy_address[0],UDP.eth2.dst_phy_address[1],UDP.eth2.dst_phy_address[2],UDP.eth2.dst_phy_address[3],UDP.eth2.dst_phy_address[4],UDP.eth2.dst_phy_address[5]);
		printf("MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n", UDP.eth2.src_phy_address[0],UDP.eth2.src_phy_address[1],UDP.eth2.src_phy_address[2],UDP.eth2.src_phy_address[3],UDP.eth2.src_phy_address[4],UDP.eth2.src_phy_address[5]);
		printf("Typ Ramki    - 0x%02x%02x\n",UDP.eth2.frame_type[0],UDP.eth2.frame_type[1]);

		printf("\n\nIP\n\n");
		printf("Wersja IP - %d\n",UDP.ip4.ver_leng.version);
		printf("IHL IP - %d\n",UDP.ip4.ver_leng.IHL);
		printf("Type Of Service - %d\n",UDP.ip4.type_of_service);
		printf("Total Length - %d\n",UDP.ip4.total_length);
		printf("Identification - 0x%02x (%d)\n",UDP.ip4.identification,UDP.ip4.identification);
		printf("Flags - 0x%02x\n",UDP.ip4.flags.fields.flags);
		printf("Offset - %d\n",UDP.ip4.flags.fields.fragment_offset);
		printf("Czas życia - %d\n",UDP.ip4.time_to_live );
		printf("Protokół - %d\n",UDP.ip4.protocol );
		printf("Suma kontrolna nagłówka - 0x%02x\n",UDP.ip4.header_checksum );
		printf("IP Nadawcy - %d.%d.%d.%d\n",UDP.ip4.src_ip[0],UDP.ip4.src_ip[1],UDP.ip4.src_ip[2],UDP.ip4.src_ip[3]);
		printf("IP Odbiorcy - %d.%d.%d.%d\n",UDP.ip4.dst_ip[0],UDP.ip4.dst_ip[1],UDP.ip4.dst_ip[2],UDP.ip4.dst_ip[3]);

		printf("\n\nUDP\n\n");
		printf("Port Nadawcy   - %d\n", UDP.udp.source_port);
		printf("Port Odbiorcy  - %d\n", UDP.udp.destination_port);
		printf("Długość        - %d\n", UDP.udp.length);
		printf("Suma kontrolna - 0x%02x",UDP.udp.checksum);
}

void print_icmp(eth_ip_icmp_packet nagl_eth_ip_icmp){
	printf("**************************** ETHERNET /IP/ ICMP  *******************************************\n");
		printf("ETHERNET\n\n");
		printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n", nagl_eth_ip_icmp.eth2.dst_phy_address[0],nagl_eth_ip_icmp.eth2.dst_phy_address[1],nagl_eth_ip_icmp.eth2.dst_phy_address[2],nagl_eth_ip_icmp.eth2.dst_phy_address[3],nagl_eth_ip_icmp.eth2.dst_phy_address[4],nagl_eth_ip_icmp.eth2.dst_phy_address[5]);
		printf("MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n", nagl_eth_ip_icmp.eth2.src_phy_address[0],nagl_eth_ip_icmp.eth2.src_phy_address[1],nagl_eth_ip_icmp.eth2.src_phy_address[2],nagl_eth_ip_icmp.eth2.src_phy_address[3],nagl_eth_ip_icmp.eth2.src_phy_address[4],nagl_eth_ip_icmp.eth2.src_phy_address[5]);
		printf("Typ Ramki    - 0x%02x%02x\n",nagl_eth_ip_icmp.eth2.frame_type[0],nagl_eth_ip_icmp.eth2.frame_type[1]);
		printf("\n\nIP\n\n");
		printf("Wersja IP - %d\n",nagl_eth_ip_icmp.ip4.ver_leng.version);
		printf("IHL IP - %d\n",nagl_eth_ip_icmp.ip4.ver_leng.IHL);
		printf("Type Of Service - %d\n",nagl_eth_ip_icmp.ip4.type_of_service);
		printf("Total Length - %d\n",nagl_eth_ip_icmp.ip4.total_length);
		printf("Identification - 0x%02x (%d)\n",nagl_eth_ip_icmp.ip4.identification,nagl_eth_ip_icmp.ip4.identification);
		printf("Flags - 0x%02x\n",nagl_eth_ip_icmp.ip4.flags.fields.flags);
		printf("Offset - %d\n",nagl_eth_ip_icmp.ip4.flags.fields.fragment_offset);
		printf("Czas życia - %d\n",nagl_eth_ip_icmp.ip4.time_to_live );
		printf("Protokół - %d\n",nagl_eth_ip_icmp.ip4.protocol );
		printf("Suma kontrolna nagłówka - 0x%02x\n",nagl_eth_ip_icmp.ip4.header_checksum);
		printf("IP Nadawcy - %d.%d.%d.%d\n",nagl_eth_ip_icmp.ip4.src_ip[0],nagl_eth_ip_icmp.ip4.src_ip[1],nagl_eth_ip_icmp.ip4.src_ip[2],nagl_eth_ip_icmp.ip4.src_ip[3]);
		printf("IP Odbiorcy - %d.%d.%d.%d\n",nagl_eth_ip_icmp.ip4.dst_ip[0],nagl_eth_ip_icmp.ip4.dst_ip[1],nagl_eth_ip_icmp.ip4.dst_ip[2],nagl_eth_ip_icmp.ip4.dst_ip[3]);

		printf("\n\nICMP\n\n");
		printf("Typ - %d\n",nagl_eth_ip_icmp.icmp.type);
		printf("Kod - %d\n",nagl_eth_ip_icmp.icmp.code);
		printf("Checksum - %02x\n",nagl_eth_ip_icmp.icmp.checksum);
		printf("Identifier       - %d (0x%02x)\n",nagl_eth_ip_icmp.icmp.identifier,nagl_eth_ip_icmp.icmp.identifier);
		printf("Sequence Number  - %d (0x%02x)\n",nagl_eth_ip_icmp.icmp.seq_number,nagl_eth_ip_icmp.icmp.seq_number);

}
void print_tcp(eth_ip_tcp_packet TCP){
	printf("\n\n**************************** ETHERNET /IP/ TCP  *******************************************\n");
	printf("ETHERNET\n\n");

	printf("MAC Odbiorcy - %02x:%02x:%02x:%02x:%02x:%02x\n", TCP.eth2.dst_phy_address[0],TCP.eth2.dst_phy_address[1],TCP.eth2.dst_phy_address[2],TCP.eth2.dst_phy_address[3],TCP.eth2.dst_phy_address[4],TCP.eth2.dst_phy_address[5]);
	printf("MAC Nadawcy  - %02x:%02x:%02x:%02x:%02x:%02x\n", TCP.eth2.src_phy_address[0],TCP.eth2.src_phy_address[1],TCP.eth2.src_phy_address[2],TCP.eth2.src_phy_address[3],TCP.eth2.src_phy_address[4],TCP.eth2.src_phy_address[5]);
	printf("Typ Ramki    - 0x%02x%02x\n",TCP.eth2.frame_type[0],TCP.eth2.frame_type[1]);

	printf("\n\nIP\n\n");
	printf("Wersja IP - %d\n",TCP.ip4.ver_leng.version);
	printf("IHL IP - %d\n",TCP.ip4.ver_leng.IHL);
	printf("Type Of Service - %d\n",TCP.ip4.type_of_service);
	printf("Total Length - %d\n",TCP.ip4.total_length);
	printf("Identification - 0x%02x (%d)\n",TCP.ip4.identification,TCP.ip4.identification);
	printf("Flags - 0x%02x\n",TCP.ip4.flags.fields.flags);
	printf("Offset - %d\n",TCP.ip4.flags.fields.fragment_offset);
	printf("Czas życia - %d\n",TCP.ip4.time_to_live );
	printf("Protokół - %d\n",TCP.ip4.protocol );
	printf("Suma kontrolna nagłówka - 0x%02x\n",TCP.ip4.header_checksum );
	printf("IP Nadawcy - %d.%d.%d.%d\n",TCP.ip4.src_ip[0],TCP.ip4.src_ip[1],TCP.ip4.src_ip[2],TCP.ip4.src_ip[3]);
	printf("IP Odbiorcy - %d.%d.%d.%d\n",TCP.ip4.dst_ip[0],TCP.ip4.dst_ip[1],TCP.ip4.dst_ip[2],TCP.ip4.dst_ip[3]);

	printf("\n\nTCP\n\n");
	printf("Port Nadawcy   - %d\n", TCP.tcp.source_port);
	printf("Port Odbiorcy  - %d\n", TCP.tcp.destination_port);
	printf("Sequence Number- 0x%02x\n",TCP.tcp.sequence_number,TCP.tcp.sequence_number);
	printf("ACK            - 0x%02x\n",TCP.tcp.ack,TCP.tcp.ack);
	printf("Data Offset    - 0x%02x\n",TCP.tcp.flags.fields.data_offset);
	printf("Reserved       - 0x%02x\n",TCP.tcp.flags.fields.reserved);
	printf("Control Bits   - 0x%02x\n",TCP.tcp.flags.fields.control_bits);
	printf("Window         - 0x%04x\n",TCP.tcp.window);
	printf("Checksum       - 0x%02x\n",TCP.tcp.checksum);
	printf("Urgent Pointer - 0x%04x\n",TCP.tcp.urgent_pointer);
	printf("Options        - 0x%04x\n",TCP.tcp.options_padding.fields.options);
	printf("Padding        - 0x%02x\n",TCP.tcp.options_padding.fields.padding);


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
