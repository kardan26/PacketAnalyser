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

void convert_raw_to_packet(eth_arp_packet *pakiet_arp,unsigned char *bufor_eth_arp,unsigned int eth_arp);

#endif /* FUNKCJE_H_ */
