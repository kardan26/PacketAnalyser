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

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>

#include "naglowki.h"
#include "funkcje.h"

int main(void) {


	//definicja zmiennych
	int s; /*deskryptor gniazda*/
	int j;
	int i = 0;
	int length = 0;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	//wskaznik do naglowka Eth
	unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	unsigned char* data = buffer + 14;


	s = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if (s == -1) {printf ("Nie moge otworzyc gniazda\n");}

	while (i<1) {
			//odbierz ramke Eth
			length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
			if (length == -1)
				printf ("Problem z odbiorem ramki \n");
			else {
				i++;
				printf ("Ramka: %d, dlugosc: %d [B]\n", i, length);
			}

			#if 1
			//wypisz zawartosc bufora
				for (j=0;j<length; j++) {
					printf ("%02x ", *(etherhead+j));
				}
				printf ("\n");
			#endif
	}

	ethernet2_frame et2;
	memcpy(&et2,etherhead,14);

	short type = et2.frame_type[0]<<8 | et2.frame_type[1];

	switch (type) {
		case 0x0800:
			printf("IPv4 \n");
			ip_frame ip4;
			memcpy(&ip4,etherhead+14,20);

			switch(ip4.protocol){
				case 0x06:
					printf("Ip Protocol Type : TCP\n");
					eth_ip_tcp_packet TCP;
					unsigned int tcp_size = sizeof(eth_ip_tcp_packet);
					convert_raw_to_tcp_packet(&TCP,etherhead,tcp_size);
					print_tcp(TCP);
					break;
				case 0x01:
					printf("Ip Protocol Type : ICMP\n");
					eth_ip_icmp_packet ICMP;
					unsigned int icmp_size = sizeof(eth_ip_icmp_packet);
					convert_raw_to_icmp_packet(&ICMP,etherhead,icmp_size);
					print_icmp(ICMP);
					break;
				case 0x11:
					printf("Ip Protocol Type : UDP\n");
					eth_ip_udp_packet UDP;
					unsigned int udp_size = sizeof(eth_ip_udp_packet);
					convert_raw_to_udp_packet(&UDP,etherhead,udp_size);
					print_udp(UDP);
					break;
				default:
					printf("Ip Protocol Type : %02x\n",ip4.protocol);
			}
			break;
		case 0x0806:
			printf("ARP \n");
			eth_arp_packet ARP;
			unsigned int arp_size = sizeof(eth_arp_packet);
			convert_raw_to_arp_packet(&ARP,etherhead,arp_size);
			print_arp(ARP);
			break;
		default:
			break;
	}

	int z;
	struct element_bufora {
		struct element_bufora *nastepny;
		struct element_bufora *poprzedni;
		struct element_bufora *pierwszy;
		unsigned char pakiet[1600];
	};
	struct element_bufora *pierwszy;

	struct element_bufora *nowy_element;
	struct element_bufora *poprzedni_element;

	pierwszy = (struct element_bufora*) malloc (sizeof(struct element_bufora));
	pierwszy->nastepny =NULL;
	pierwszy->poprzedni = NULL;
	pierwszy->nastepny =pierwszy;
	memset (pierwszy->pakiet,0,1600);

	poprzedni_element = pierwszy;

	return EXIT_SUCCESS;
}
