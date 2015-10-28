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
	ethernet2_frame eth2;
	arp_frame arp;
	unsigned char data[1476]; //1500-24
} eth_arp_packet;

#endif /* NAGLOWKI_H_ */
