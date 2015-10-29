/*
 * naglowki.h
 *
 *  Created on: Oct 28, 2015
 *      Author: daniel
 */

#ifndef NAGLOWKI_H_
#define NAGLOWKI_H_

typedef struct {
	unsigned char dst_phy_address[6];
	unsigned char src_phy_address[6];
	unsigned char frame_type[2];
}ethernet2_frame;


typedef struct{
	unsigned char phy_address_space[2];
	unsigned char pro_address_space[2];
	unsigned char phy_address_length;
	unsigned char pro_address_length;
	unsigned char opcode[2];
	unsigned char source_phy_addr[6];
	unsigned char source_pro_addr[4];
	unsigned char destination_phy_addr[6];
	unsigned char destination_pro_addr[4];

}arp_frame;

typedef struct {
	unsigned char IHL:4,
				  version:4;

} ip_version_length;

typedef union {
	struct{
		unsigned short fragment_offset:13,
						          flags:3;
	} fields;
	unsigned short bits;

}ip_flags_and_offset;

typedef struct {
	ip_version_length ver_leng;
	unsigned char type_of_service;
	unsigned short total_length;
	unsigned short identification;
	ip_flags_and_offset flags;
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned char src_ip[4];
	unsigned char dst_ip[4];
}ip_frame;

typedef struct {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short identifier;
	unsigned short seq_number;

}icmp_frame;

typedef struct {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned short length;
	unsigned short checksum;
}udp_frame;


typedef struct{
	unsigned short control_bits:6,
				   reserved    :6,
				   data_offset :4;
}tcp_flags;

typedef struct{
	unsigned int   padding:8,
				   options:24;
}tcp_options_padding;

typedef struct {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned int sequence_number;
	unsigned int ack;
	tcp_flags flags;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;


}tcp_frame;

typedef struct {
	ethernet2_frame eth2;
	arp_frame arp;
	unsigned char data[1476]; //1500-24
} eth_arp_packet;

typedef struct {
	ethernet2_frame eth2;
	ip_frame ip4;
	icmp_frame icmp;
	unsigned char data[1464];//1500-14-18-4
}eth_ip_icmp_packet;

typedef struct{
	ethernet2_frame eth2;
	ip_frame ip4;
	udp_frame udp;
	unsigned char data[1460]; //1500-14-18-8

}eth_ip_udp_packet;

typedef struct{
	ethernet2_frame eth2;
	ip_frame ip4;
	tcp_frame tcp;
	unsigned char data[1448]; //1500-14-18-20

}eth_ip_tcp_packet;

#endif /* NAGLOWKI_H_ */
