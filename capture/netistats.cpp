/* Copyright 2003-2005 Charles Robert Simpson, Jr.
 *
 * This file is part of NETI@home.
 * 
 * NETI@home is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * NETI@home is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NETI@home; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>

#ifndef WIN32
#include <sys/time.h>	// for struct timeval macros
#include <unistd.h>	// for gethostid()
#include <netdb.h>	// for gethostbyname()
#include <string>
#else
	typedef u_long in_addr_t;
#endif

#include "netistats.h"
#include "timersub.h"
#include "checksum.h"

#define NETGEO_IP "192.172.226.77"	// netgeo
// flows are counted as expired after RETIRE_TIME seconds
#define RETIRE_TIME 120
// TCP timeout time (in usecs)
#define TIMEOUT_TIME 200000

map<struct Flow_Key, class UDP_Flow, fkcompare> UDP_Flows;
map<struct Flow_Key, class TCP_Flow, fkcompare> TCP_Flows;
map<struct Flow_Key_NoPorts, class ICMP_Flow, fkcompare_noports> ICMP_Flows;
map<struct Flow_Key, class UDP_Flow, fkcompare> old_UDP_Flows;
map<struct Flow_Key, class TCP_Flow, fkcompare> old_TCP_Flows;
map<struct Flow_Key_NoPorts, class ICMP_Flow, fkcompare_noports> old_ICMP_Flows;
list<class IGMP_Flow> old_IGMP_Flows;

double htond(double d);
int isPrivate(string address);
int isLoopback(struct in_addr in);
int whichEqualIP(struct in_addr src, struct in_addr dest);
int isBroadcastIP(struct in_addr in);

// TCP Packet (Transmission Control Protocol)
void NETITCP(Packet *p) {
/*
	struct timeval result;
	struct timeval timeoutval;
	struct Flow_Key fk;
	struct TCP_Packet packet;
	int sackperm = 0;
	int mss = -1;
	timeoutval.tv_sec = 0;
	timeoutval.tv_usec = TIMEOUT_TIME;
	uint8_t wscale = 0;

	list<struct TCP_Packet>::iterator packetiterator;
	map<struct Flow_Key, class TCP_Flow, fkcompare>::iterator tcpiterator;

	NETIIP_struct ip_struct;
	NETIIP(p, &ip_struct);

	if(p->tcph == NULL) {
		// need to do some kind of PacketError thing (count as dropped???)
		return;
	}

	// Don't want to capture packets intended for NETI server
	// Don't want to capture Loopback packets
	if(ip_struct.dest_ip.s_addr == DEST_IP.s_addr || isLoopback(ip_struct.src_ip) || isLoopback(ip_struct.dest_ip)) {
		return;
	}
	if(p->tcp_option_count != 0) {
		if(p->tcp_option_count > 40) {
			// bad
		}
		for(int i = 0; i < (int) p->tcp_option_count; i++) {
			switch(p->tcp_options[i].code) {
				// MSS
				case TCPOPT_MAXSEG:
					mss = ntohs(*(u_short *)p->tcp_options[i].data);	// MSS (16 bits)
					break;
				// SACK
				case TCPOPT_SACKOK:			// SackOK
					sackperm = 1;
					break;
			// Unused Options - Fall Through
				case TCPOPT_EOL:		// EOL
				case TCPOPT_NOP:		// NOP
					break;
				// Window Scaling
				case TCPOPT_WSCALE:
					wscale = p->tcp_options[i].data[0];	// WS
					break;
			// Unused Options - Fall Through
				case TCPOPT_SACK:
					//p->tcp_options[i].data	// Sack (16 bits)
					//(p->tcp_options[i].data) + 2	// @ (16 bits)
				case TCPOPT_ECHO:
					//p->tcp_options[i].data	// Echo (32 bits)
				case TCPOPT_ECHOREPLY:
					//p->tcp_options[i].data	// Echo Rep (32 bits)
				case TCPOPT_TIMESTAMP:
					//p->tcp_options[i].data	// TS (32 bits)
					//(p->tcp_options[i].data) + 4	// (32 bits)
				case TCPOPT_CC:
					//p->tcp_options[i].data	// CC (32 bits)
				case TCPOPT_CCNEW:
					//p->tcp_options[i].data	// CCNEW (32 bits)
				case TCPOPT_CCECHO:
					//p->tcp_options[i].data	// CCECHO (32 bits)
				default:
					//if(p->tcp_options[i].len) {
					//	p->tcp_options[i].code	// Opt
					//	(int)p->tcp_options[i].len	// Len
					//	for(int j = 0; j < p->tcp_options[i].len; j++) {
					//		p->tcp_options[i].data[j]
					//	}
					//}
					//else {
					//	p->tcp_options[i].code	// Opt
					//}
					break;
			}
		}
	}

	// Place all variables into TCP_Flow
	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
		fk.my_ip = ip_struct.src_ip;
		fk.remote_ip = ip_struct.dest_ip;
		fk.my_port = ip_struct.src_port;
		fk.remote_port = ip_struct.dest_port;
	}
	else {
		fk.my_ip = ip_struct.dest_ip;
		fk.remote_ip = ip_struct.src_ip;
		fk.my_port = ip_struct.dest_port;
		fk.remote_port = ip_struct.src_port;
	}
	if(TCP_Flows.count(fk)) {
		// insert new data to existing flow
		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Sender (Local)

			// Window Size
			if(ntohs(p->tcph->th_win) > TCP_Flows[fk].stats.local_max_win) {
				TCP_Flows[fk].stats.local_max_win = ntohs(p->tcph->th_win);
			}
			else {
				if(ntohs(p->tcph->th_win) < TCP_Flows[fk].stats.local_min_win)
					TCP_Flows[fk].stats.local_min_win = ntohs(p->tcph->th_win);
			}
			// If ACK, then check for duplicate and triplicate ACK
			if((p->tcph->th_flags & TH_ACK) && (TCP_Flows[fk].last_ack_num_sent == ntohl(p->tcph->th_ack))) {
				if(TCP_Flows[fk].last_last_ack_num_sent == ntohl(p->tcph->th_ack)) {
					TCP_Flows[fk].stats.num_trip_acks_sent++;
				}
				else {
					TCP_Flows[fk].stats.num_dup_acks_sent++;
				}
			}
			TCP_Flows[fk].last_last_ack_num_sent = TCP_Flows[fk].last_ack_num_sent;
			TCP_Flows[fk].last_ack_num_sent = ntohl(p->tcph->th_ack);
			// Check to see if retransmission
			if(TCP_Flows[fk].highest_seq_num_sent >= ntohl(p->tcph->th_seq)) {
				TCP_Flows[fk].stats.num_retrans_sent++;
				TCP_Flows[fk].stats.bytes_retrans_sent += p->dsize;
			}
			// High water mark
			if(ntohl(p->tcph->th_seq) > TCP_Flows[fk].highest_seq_num_sent) {
				TCP_Flows[fk].highest_seq_num_sent = ntohl(p->tcph->th_seq);
			}

			// TTL
			if(ip_struct.ttl > TCP_Flows[fk].stats.local_max_ttl) {
				TCP_Flows[fk].stats.local_max_ttl = ip_struct.ttl;
			}
			else if(ip_struct.ttl < TCP_Flows[fk].stats.local_min_ttl) {
				TCP_Flows[fk].stats.local_min_ttl = ip_struct.ttl;
			}

			if(p->dsize > TCP_Flows[fk].stats.max_packet_size_sent) {
				TCP_Flows[fk].stats.max_packet_size_sent = p->dsize;
			}
			else if(p->dsize < TCP_Flows[fk].stats.min_packet_size_sent) {
				TCP_Flows[fk].stats.min_packet_size_sent = p->dsize;
			}
		}
		else {
			// Receiver (Remote)

			// Window Size
			if(ntohs(p->tcph->th_win) > TCP_Flows[fk].stats.remote_max_win) {
				TCP_Flows[fk].stats.remote_max_win = ntohs(p->tcph->th_win);
			}
			else if(ntohs(p->tcph->th_win) < TCP_Flows[fk].stats.remote_min_win) {
				TCP_Flows[fk].stats.remote_min_win = ntohs(p->tcph->th_win);
			}
			// If ACK, then check for duplicate and triplicate ACK
			if((p->tcph->th_flags & TH_ACK) && (TCP_Flows[fk].last_ack_num_recv == ntohl(p->tcph->th_ack))) {
				if(TCP_Flows[fk].last_last_ack_num_recv == ntohl(p->tcph->th_ack)) {
					TCP_Flows[fk].stats.num_trip_acks_received++;
				}
				else {
					TCP_Flows[fk].stats.num_dup_acks_received++;
				}
			}
			TCP_Flows[fk].last_last_ack_num_recv = TCP_Flows[fk].last_ack_num_recv;
			TCP_Flows[fk].last_ack_num_recv = ntohl(p->tcph->th_ack);
			// Check to see if retransmission
	// THIS MAY NOT BE RIGHT, HOW CAN I TELL THE DIFFERENCE BETWEEN REORDER AND RETRANSMISSION WHEN RECEIVING???
	// I AGREE WITH THE ABOVE STATEMENT, SO THE FOLLOWING CODE HAS BEEN COMMENTED OUT
			//if(TCP_Flows[fk].highest_seq_num_recv >= ntohl(p->tcph->th_seq)) {
			//	TCP_Flows[fk].stats.num_retrans++;
			//	TCP_Flows[fk].stats.bytes_retrans += p->dsize;
			//}
			// High water mark
			if(ntohl(p->tcph->th_seq) > TCP_Flows[fk].highest_seq_num_recv) {
				TCP_Flows[fk].highest_seq_num_recv = ntohl(p->tcph->th_seq);
			}
			// Check to see if in order
			if(TCP_Flows[fk].next_seq_num == ntohl(p->tcph->th_seq)) {
				TCP_Flows[fk].stats.num_in_order++;
			}
			else {
				TCP_Flows[fk].stats.num_out_order++;
			}
			if(p->tcph->th_flags & TH_ACK) {
				TCP_Flows[fk].time_last_ack = ip_struct.ts;
			}

			// TTL
			if(ip_struct.ttl > TCP_Flows[fk].stats.remote_max_ttl)
				TCP_Flows[fk].stats.remote_max_ttl = ip_struct.ttl;
			else {
				if(ip_struct.ttl < TCP_Flows[fk].stats.remote_min_ttl)
					TCP_Flows[fk].stats.remote_min_ttl = ip_struct.ttl;
			}

			if(p->dsize > TCP_Flows[fk].stats.max_packet_size_received) {
				TCP_Flows[fk].stats.max_packet_size_received = p->dsize;
			}
			else if(p->dsize < TCP_Flows[fk].stats.min_packet_size_received) {
				TCP_Flows[fk].stats.min_packet_size_received = p->dsize;
			}
		}


		// Check for Inactivity Period
		// (This could give false data if the channel is just idle, which would
		// be rare hopefully)
		TIMERSUB(&ip_struct.ts, &(TCP_Flows[fk].time_last_ack), &result);
		if(timercmp(&result, &timeoutval, >)) {
			TCP_Flows[fk].stats.num_inactivity_periods++;
		}
	}
	else {
		// insert new flow
		// Map Stuff
		// Send fk.remote_ip to NETIMap
		string ipdata(inet_ntoa(fk.remote_ip));
		if(!isPrivate(ipdata)) {
			sendto(netimapfd, ipdata.c_str(), strlen(ipdata.c_str()),0, (sockaddr *)&netimap_addr, sizeof(netimap_addr));
		}

		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Sender (Local)

			TCP_Flows[fk].stats.max_packet_size_sent = p->dsize;
			TCP_Flows[fk].stats.min_packet_size_sent = p->dsize;
		}
		else {
			// Receiver (Remote)

			TCP_Flows[fk].stats.max_packet_size_received = p->dsize;
			TCP_Flows[fk].stats.min_packet_size_received = p->dsize;
		}

		// LOW privacy
		if(privacylevel == 0) {
			TCP_Flows[fk].stats.local_ip = fk.my_ip;
			TCP_Flows[fk].stats.remote_ip = fk.remote_ip;
		}
		// HIGH privacy
		else if(privacylevel == 2) {
			TCP_Flows[fk].stats.local_ip.s_addr = 0;
			TCP_Flows[fk].stats.remote_ip.s_addr = 0;
		}
		// MEDIUM (default) privacy
		else {
			// Only keep network part of address
			if(isBroadcastIP(fk.my_ip) == 1) {
				TCP_Flows[fk].stats.local_ip = fk.my_ip;
			}
			else {
				TCP_Flows[fk].stats.local_ip.s_addr = (fk.my_ip.s_addr & pv.netmask);
			}

			if(isBroadcastIP(fk.remote_ip) == 1) {
				TCP_Flows[fk].stats.remote_ip = fk.remote_ip;
			}
			else {
				TCP_Flows[fk].stats.remote_ip.s_addr = (fk.remote_ip.s_addr & pv.netmask);
			}
		}
		TCP_Flows[fk].stats.local_port = fk.my_port;
		TCP_Flows[fk].stats.remote_port = fk.remote_port;
		TCP_Flows[fk].stats.time_established = ip_struct.ts;

		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Sender (Local)
			TCP_Flows[fk].stats.local_max_win = ntohs(p->tcph->th_win);
			TCP_Flows[fk].stats.local_min_win = ntohs(p->tcph->th_win);
			// High water mark
			TCP_Flows[fk].highest_seq_num_sent = ntohl(p->tcph->th_seq);

			// TTL
			TCP_Flows[fk].stats.local_max_ttl = ip_struct.ttl;
			TCP_Flows[fk].stats.local_min_ttl = ip_struct.ttl;
		}
		else {
			// Receiver (Remote)
			TCP_Flows[fk].stats.remote_max_win = ntohs(p->tcph->th_win);
			TCP_Flows[fk].stats.remote_min_win = ntohs(p->tcph->th_win);
			// High water mark
			TCP_Flows[fk].highest_seq_num_recv = ntohl(p->tcph->th_seq);
			if(p->tcph->th_flags & TH_ACK) {
				TCP_Flows[fk].time_last_ack = ip_struct.ts;
			}

			// TTL
			TCP_Flows[fk].stats.remote_max_ttl = ip_struct.ttl;
			TCP_Flows[fk].stats.remote_min_ttl = ip_struct.ttl;
		}
	}

	// Look for Retransmissions
	packetiterator = TCP_Flows[fk].packets.begin();
	while(packetiterator != TCP_Flows[fk].packets.end()) {
		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Packet is a retrans
			if(packetiterator->seq_num == ntohl(p->tcph->th_seq) && packetiterator->mine) {
				packetiterator->retrans = true;
				break;
			}
			else {
				packetiterator++;
			}
		}
		else {
			// Packet is a retrans
			if(packetiterator->seq_num == ntohl(p->tcph->th_seq) && !packetiterator->mine) {
				packetiterator->retrans = true;
				break;
			}
			else {
				packetiterator++;
			}
		}
	}
	// Packet is not a retrans
	if(packetiterator == TCP_Flows[fk].packets.end()) {
		packet.seq_num = ntohl(p->tcph->th_seq);
		packet.length = p->dsize;
		packet.xmissiontime = ip_struct.ts;
		packet.acked = false;
		packet.retrans = false;
		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			packet.mine = true;
		}
		else {
			packet.mine = false;
		}
		if(p->tcph->th_flags & TH_SYN) {
			packet.syn = true;
		}
		else {
			packet.syn = false;
		}
		TCP_Flows[fk].packets.push_back(packet);
	}

	// Check TCP Checksum
	if(p->csum_flags & CSE_TCP) {
		TCP_Flows[fk].stats.num_badtcpsum++;
	}

	// Check IP Checksum
	if(!ip_struct.checksumcorrect) {
		TCP_Flows[fk].stats.num_badipsum++;
	}

	TCP_Flows[fk].time_last = ip_struct.ts;

	// Next sequence number expected to receive
	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) != 1) {
		TCP_Flows[fk].next_seq_num = ntohl(p->tcph->th_seq) + p->dsize;
	}

	// Check to see if Pure SYN (for SYN RTT and Connection Establishment Method)
	if((p->tcph->th_flags & TH_SYN) && !(p->tcph->th_flags & TH_ACK)) {
		if(!(TCP_Flows[fk].gotSyn)) {
			TCP_Flows[fk].syntime.tv_sec = ip_struct.ts.tv_sec;
			TCP_Flows[fk].syntime.tv_usec = ip_struct.ts.tv_usec;
			TCP_Flows[fk].gotSyn = true;

			// Connection Establishment Method
			if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
				// Sender (Local)
				TCP_Flows[fk].stats.con_estb_method = SYN_SENT;
			}
			else {
				// Receiver (Remote)
				TCP_Flows[fk].stats.con_estb_method = SYN_RECEIVED;
			}
		}
		else {
			TCP_Flows[fk].synerr = true;
		}
	}
	// Pure ACK (for SYN RTT)
	if((p->tcph->th_flags & TH_ACK) && !(p->tcph->th_flags & TH_SYN) && !(TCP_Flows[fk].gotSynRtt)) {
		if(!(TCP_Flows[fk].gotSyn)) {
			TCP_Flows[fk].synerr = true;
		}
		else {
			TIMERSUB(&ip_struct.ts, &TCP_Flows[fk].syntime, &TCP_Flows[fk].stats.syn_rtt);
			TCP_Flows[fk].gotSynRtt = true;
		}
	}

	// Check to see if ACK
	if(p->tcph->th_flags & TH_ACK) {
		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Sender (Local)
			TCP_Flows[fk].stats.num_acks_sent++;
		}
		else {
			// Receiver (Remote)
			TCP_Flows[fk].stats.num_acks_received++;
		}

		packetiterator = TCP_Flows[fk].packets.begin();
		while(packetiterator != TCP_Flows[fk].packets.end()) {
			if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 0) {
				// Receiver (Remote)
				if(packetiterator->seq_num <= ntohl(p->tcph->th_ack) && packetiterator->mine) {
					if(!(packetiterator->acked)) {
						packetiterator->acked = true;

						if(!(packetiterator->retrans) && ((packetiterator->syn && packetiterator->seq_num + 1 == ntohl(p->tcph->th_ack)) || (!(packetiterator->syn) && packetiterator->seq_num + packetiterator->length == ntohl(p->tcph->th_ack)))) {
							// calculate RTT
							TCP_Flows[fk].num_rtt++;
							TIMERSUB(&ip_struct.ts, &(packetiterator->xmissiontime), &result);
							if(timercmp(&result, &(TCP_Flows[fk].stats.min_rtt), <)) {
								TCP_Flows[fk].stats.min_rtt = result;
							}
							if(timercmp(&result, &(TCP_Flows[fk].stats.max_rtt), >)) {
								TCP_Flows[fk].stats.max_rtt = result;
							}
							// Maybe should check for overflow
							TCP_Flows[fk].stats.ave_rtt.tv_sec = ((TCP_Flows[fk].stats.ave_rtt.tv_sec * (TCP_Flows[fk].num_rtt - 1)) + result.tv_sec) / TCP_Flows[fk].num_rtt;
							TCP_Flows[fk].stats.ave_rtt.tv_usec = ((TCP_Flows[fk].stats.ave_rtt.tv_usec * (TCP_Flows[fk].num_rtt - 1)) + result.tv_usec) / TCP_Flows[fk].num_rtt;
						}
					}
				}
			}
			if(packetiterator->acked) {
				// Remove from list
				// Hopefully it is safe to assume that ACKed packets will no longer be needed
				TCP_Flows[fk].packets.erase(packetiterator);
				packetiterator = TCP_Flows[fk].packets.begin();
			}
			else {
				packetiterator++;
			}
		}
	}

	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
		// Sender (Local)
		TCP_Flows[fk].stats.packets_sent++;
		TCP_Flows[fk].stats.bytes_sent += p->dsize;
		TCP_Flows[fk].stats.local_ave_win = ((TCP_Flows[fk].stats.local_ave_win * (TCP_Flows[fk].stats.packets_sent - 1)) + ntohs(p->tcph->th_win)) / TCP_Flows[fk].stats.packets_sent;
		if(mss != -1) {
			// Maybe should record number of changes and average, min, max
			TCP_Flows[fk].stats.local_mss = mss;
		}
		// Check SACK Permitted Option
		if(sackperm) {
			TCP_Flows[fk].stats.local_SACK_perm++;
		}

		// Check for Fragmentation
		if(ip_struct.frag) {
			TCP_Flows[fk].stats.num_frag_sent++;
		}

		// Check the Don't Fragment Flag
		if(ip_struct.df) {
			TCP_Flows[fk].stats.num_dontfrag_sent++;
		}

		// Urgent Data
		if(p->tcph->th_flags & TH_URG) {
			TCP_Flows[fk].stats.num_urg_sent++;
		}

		// PUSH Flag
		if(p->tcph->th_flags & TH_PUSH) {
			TCP_Flows[fk].stats.num_push_sent++;
		}

		// ECN-ECHO Flag
		if(p->tcph->th_flags & TH_RES2) {
			TCP_Flows[fk].stats.num_ecnecho_sent++;
		}

		// CWR Flag
		if(p->tcph->th_flags & TH_RES1) {
			TCP_Flows[fk].stats.num_cwr_sent++;
		}

		// Window Scaling
		if(wscale) {
			TCP_Flows[fk].stats.local_win_scale = wscale;
		}

		TCP_Flows[fk].stats.ave_packet_size_sent = ((TCP_Flows[fk].stats.ave_packet_size_sent * (TCP_Flows[fk].stats.packets_sent - 1)) + p->dsize) / TCP_Flows[fk].stats.packets_sent;
	}
	else {
		// Receiver (Remote)
		TCP_Flows[fk].stats.packets_received++;
		TCP_Flows[fk].stats.bytes_received += p->dsize;
		TCP_Flows[fk].stats.remote_ave_win = ((TCP_Flows[fk].stats.remote_ave_win * (TCP_Flows[fk].stats.packets_received - 1)) + ntohs(p->tcph->th_win)) / TCP_Flows[fk].stats.packets_received;
		if(mss != -1) {
			// Maybe should record number of changes and average, min, max
			TCP_Flows[fk].stats.remote_mss = mss;
		}
		// Check SACK Permitted Option
		if(sackperm) {
			TCP_Flows[fk].stats.remote_SACK_perm++;
		}

		// Check for Fragmentation
		if(ip_struct.frag) {
			TCP_Flows[fk].stats.num_frag_received++;
		}

		// Check the Don't Fragment Flag
		if(ip_struct.df) {
			TCP_Flows[fk].stats.num_dontfrag_received++;
		}

		// Urgent Data
		if(p->tcph->th_flags & TH_URG) {
			TCP_Flows[fk].stats.num_urg_received++;
		}

		// PUSH Flag
		if(p->tcph->th_flags & TH_PUSH) {
			TCP_Flows[fk].stats.num_push_received++;
		}

		// ECN-ECHO Flag
		if(p->tcph->th_flags & TH_RES2) {
			TCP_Flows[fk].stats.num_ecnecho_received++;
		}

		// CWR Flag
		if(p->tcph->th_flags & TH_RES1) {
			TCP_Flows[fk].stats.num_cwr_received++;
		}

		// Window Scaling
		if(wscale) {
			TCP_Flows[fk].stats.remote_win_scale = wscale;
		}

		TCP_Flows[fk].stats.ave_packet_size_received = ((TCP_Flows[fk].stats.ave_packet_size_received * (TCP_Flows[fk].stats.packets_received - 1)) + p->dsize) / TCP_Flows[fk].stats.packets_received;
	}

	// Remove if FIN sent or received
	if(p->tcph->th_flags & TH_FIN) {
		TCP_Flows[fk].stats.time_closed = ip_struct.ts;

		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Sender (Local)
			TCP_Flows[fk].stats.closure_method = FIN_SENT;
		}
		else {
			// Receiver (Remote)
			TCP_Flows[fk].stats.closure_method = FIN_RECEIVED;
		}

		tcpiterator = TCP_Flows.find(fk);

		// But first, hton everything
		tcpiterator->second.stats.type = htonl(tcpiterator->second.stats.type);
		tcpiterator->second.stats.time_established.tv_sec = htonl(tcpiterator->second.stats.time_established.tv_sec);
		tcpiterator->second.stats.time_established.tv_usec = htonl(tcpiterator->second.stats.time_established.tv_usec);
		tcpiterator->second.stats.time_closed.tv_sec = htonl(tcpiterator->second.stats.time_closed.tv_sec);
		tcpiterator->second.stats.time_closed.tv_usec = htonl(tcpiterator->second.stats.time_closed.tv_usec);
		tcpiterator->second.stats.local_port = htons(tcpiterator->second.stats.local_port);
		tcpiterator->second.stats.remote_port = htons(tcpiterator->second.stats.remote_port);
		tcpiterator->second.stats.num_badtcpsum = htonl(tcpiterator->second.stats.num_badtcpsum);
		tcpiterator->second.stats.num_badipsum = htonl(tcpiterator->second.stats.num_badipsum);
		tcpiterator->second.stats.packets_sent = htonl(tcpiterator->second.stats.packets_sent);
		tcpiterator->second.stats.packets_received = htonl(tcpiterator->second.stats.packets_received);
		tcpiterator->second.stats.bytes_sent = htonl(tcpiterator->second.stats.bytes_sent);
		tcpiterator->second.stats.bytes_received = htonl(tcpiterator->second.stats.bytes_received);
		tcpiterator->second.stats.num_acks_sent = htonl(tcpiterator->second.stats.num_acks_sent);
		tcpiterator->second.stats.num_acks_received = htonl(tcpiterator->second.stats.num_acks_received);
		tcpiterator->second.stats.num_dup_acks_sent = htonl(tcpiterator->second.stats.num_dup_acks_sent);
		tcpiterator->second.stats.num_dup_acks_received = htonl(tcpiterator->second.stats.num_dup_acks_received);
		tcpiterator->second.stats.num_trip_acks_sent = htonl(tcpiterator->second.stats.num_trip_acks_sent);
		tcpiterator->second.stats.num_trip_acks_received = htonl(tcpiterator->second.stats.num_trip_acks_received);
		tcpiterator->second.stats.min_packet_size_sent = htons(tcpiterator->second.stats.min_packet_size_sent);
		tcpiterator->second.stats.min_packet_size_received = htons(tcpiterator->second.stats.min_packet_size_received);
		tcpiterator->second.stats.ave_packet_size_sent = htons(tcpiterator->second.stats.ave_packet_size_sent);
		tcpiterator->second.stats.ave_packet_size_received = htons(tcpiterator->second.stats.ave_packet_size_received);
		tcpiterator->second.stats.max_packet_size_sent = htons(tcpiterator->second.stats.max_packet_size_sent);
		tcpiterator->second.stats.max_packet_size_received = htons(tcpiterator->second.stats.max_packet_size_received);
		tcpiterator->second.stats.num_urg_sent = htonl(tcpiterator->second.stats.num_urg_sent);
		tcpiterator->second.stats.num_urg_received = htonl(tcpiterator->second.stats.num_urg_received);
		tcpiterator->second.stats.num_push_sent = htonl(tcpiterator->second.stats.num_push_sent);
		tcpiterator->second.stats.num_push_received = htonl(tcpiterator->second.stats.num_push_received);
		tcpiterator->second.stats.num_ecnecho_sent = htonl(tcpiterator->second.stats.num_ecnecho_sent);
		tcpiterator->second.stats.num_ecnecho_received = htonl(tcpiterator->second.stats.num_ecnecho_received);
		tcpiterator->second.stats.num_cwr_sent = htonl(tcpiterator->second.stats.num_cwr_sent);
		tcpiterator->second.stats.num_cwr_received = htonl(tcpiterator->second.stats.num_cwr_received);
		tcpiterator->second.stats.num_frag_sent = htonl(tcpiterator->second.stats.num_frag_sent);
		tcpiterator->second.stats.num_frag_received = htonl(tcpiterator->second.stats.num_frag_received);
		tcpiterator->second.stats.num_dontfrag_sent = htonl(tcpiterator->second.stats.num_dontfrag_sent);
		tcpiterator->second.stats.num_dontfrag_received = htonl(tcpiterator->second.stats.num_dontfrag_received);
		tcpiterator->second.stats.local_min_win = htons(tcpiterator->second.stats.local_min_win);
		tcpiterator->second.stats.remote_min_win = htons(tcpiterator->second.stats.remote_min_win);
		tcpiterator->second.stats.local_ave_win = htons(tcpiterator->second.stats.local_ave_win);
		tcpiterator->second.stats.remote_ave_win = htons(tcpiterator->second.stats.remote_ave_win);
		tcpiterator->second.stats.local_max_win = htons(tcpiterator->second.stats.local_max_win);
		tcpiterator->second.stats.remote_max_win = htons(tcpiterator->second.stats.remote_max_win);
		tcpiterator->second.stats.local_min_ttl = htonl(tcpiterator->second.stats.local_min_ttl);
		tcpiterator->second.stats.local_max_ttl = htonl(tcpiterator->second.stats.local_max_ttl);
		tcpiterator->second.stats.remote_min_ttl = htonl(tcpiterator->second.stats.remote_min_ttl);
		tcpiterator->second.stats.remote_max_ttl = htonl(tcpiterator->second.stats.remote_max_ttl);
		tcpiterator->second.stats.num_retrans_sent = htonl(tcpiterator->second.stats.num_retrans_sent);
		tcpiterator->second.stats.num_retrans_received = htonl(tcpiterator->second.stats.num_retrans_received);
		tcpiterator->second.stats.bytes_retrans_sent = htonl(tcpiterator->second.stats.bytes_retrans_sent);
		tcpiterator->second.stats.bytes_retrans_received = htonl(tcpiterator->second.stats.bytes_retrans_received);
		tcpiterator->second.stats.num_inactivity_periods = htonl(tcpiterator->second.stats.num_inactivity_periods);
		tcpiterator->second.stats.min_rtt.tv_sec = htonl(tcpiterator->second.stats.min_rtt.tv_sec);
		tcpiterator->second.stats.min_rtt.tv_usec = htonl(tcpiterator->second.stats.min_rtt.tv_usec);
		tcpiterator->second.stats.max_rtt.tv_sec = htonl(tcpiterator->second.stats.max_rtt.tv_sec);
		tcpiterator->second.stats.max_rtt.tv_usec = htonl(tcpiterator->second.stats.max_rtt.tv_usec);
		tcpiterator->second.stats.ave_rtt.tv_sec = htonl(tcpiterator->second.stats.ave_rtt.tv_sec);
		tcpiterator->second.stats.ave_rtt.tv_usec = htonl(tcpiterator->second.stats.ave_rtt.tv_usec);
		tcpiterator->second.stats.syn_rtt.tv_sec = htonl(tcpiterator->second.stats.syn_rtt.tv_sec);
		tcpiterator->second.stats.syn_rtt.tv_usec = htonl(tcpiterator->second.stats.syn_rtt.tv_usec);
		tcpiterator->second.stats.num_in_order = htonl(tcpiterator->second.stats.num_in_order);
		tcpiterator->second.stats.num_out_order = htonl(tcpiterator->second.stats.num_out_order);
		tcpiterator->second.stats.local_mss = htonl(tcpiterator->second.stats.local_mss);
		tcpiterator->second.stats.remote_mss = htonl(tcpiterator->second.stats.remote_mss);
		tcpiterator->second.stats.drops = htonl(tcpiterator->second.stats.drops);


		old_TCP_Flows.insert(*tcpiterator);
		TCP_Flows.erase(tcpiterator);
	}
	// Remove if RST sent or received
	else if(p->tcph->th_flags & TH_RST) {
		TCP_Flows[fk].stats.time_closed = ip_struct.ts;

		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Sender
			TCP_Flows[fk].stats.closure_method = RST_SENT;
		}
		else {
			// Receiver
			TCP_Flows[fk].stats.closure_method = RST_RECEIVED;
		}

		tcpiterator = TCP_Flows.find(fk);

		// But first, hton everything
		tcpiterator->second.stats.type = htonl(tcpiterator->second.stats.type);
		tcpiterator->second.stats.time_established.tv_sec = htonl(tcpiterator->second.stats.time_established.tv_sec);
		tcpiterator->second.stats.time_established.tv_usec = htonl(tcpiterator->second.stats.time_established.tv_usec);
		tcpiterator->second.stats.time_closed.tv_sec = htonl(tcpiterator->second.stats.time_closed.tv_sec);
		tcpiterator->second.stats.time_closed.tv_usec = htonl(tcpiterator->second.stats.time_closed.tv_usec);
		tcpiterator->second.stats.local_port = htons(tcpiterator->second.stats.local_port);
		tcpiterator->second.stats.remote_port = htons(tcpiterator->second.stats.remote_port);
		tcpiterator->second.stats.num_badtcpsum = htonl(tcpiterator->second.stats.num_badtcpsum);
		tcpiterator->second.stats.num_badipsum = htonl(tcpiterator->second.stats.num_badipsum);
		tcpiterator->second.stats.packets_sent = htonl(tcpiterator->second.stats.packets_sent);
		tcpiterator->second.stats.packets_received = htonl(tcpiterator->second.stats.packets_received);
		tcpiterator->second.stats.bytes_sent = htonl(tcpiterator->second.stats.bytes_sent);
		tcpiterator->second.stats.bytes_received = htonl(tcpiterator->second.stats.bytes_received);
		tcpiterator->second.stats.num_acks_sent = htonl(tcpiterator->second.stats.num_acks_sent);
		tcpiterator->second.stats.num_acks_received = htonl(tcpiterator->second.stats.num_acks_received);
		tcpiterator->second.stats.num_dup_acks_sent = htonl(tcpiterator->second.stats.num_dup_acks_sent);
		tcpiterator->second.stats.num_dup_acks_received = htonl(tcpiterator->second.stats.num_dup_acks_received);
		tcpiterator->second.stats.num_trip_acks_sent = htonl(tcpiterator->second.stats.num_trip_acks_sent);
		tcpiterator->second.stats.num_trip_acks_received = htonl(tcpiterator->second.stats.num_trip_acks_received);
		tcpiterator->second.stats.min_packet_size_sent = htons(tcpiterator->second.stats.min_packet_size_sent);
		tcpiterator->second.stats.min_packet_size_received = htons(tcpiterator->second.stats.min_packet_size_received);
		tcpiterator->second.stats.ave_packet_size_sent = htons(tcpiterator->second.stats.ave_packet_size_sent);
		tcpiterator->second.stats.ave_packet_size_received = htons(tcpiterator->second.stats.ave_packet_size_received);
		tcpiterator->second.stats.max_packet_size_sent = htons(tcpiterator->second.stats.max_packet_size_sent);
		tcpiterator->second.stats.max_packet_size_received = htons(tcpiterator->second.stats.max_packet_size_received);
		tcpiterator->second.stats.num_urg_sent = htonl(tcpiterator->second.stats.num_urg_sent);
		tcpiterator->second.stats.num_urg_received = htonl(tcpiterator->second.stats.num_urg_received);
		tcpiterator->second.stats.num_push_sent = htonl(tcpiterator->second.stats.num_push_sent);
		tcpiterator->second.stats.num_push_received = htonl(tcpiterator->second.stats.num_push_received);
		tcpiterator->second.stats.num_ecnecho_sent = htonl(tcpiterator->second.stats.num_ecnecho_sent);
		tcpiterator->second.stats.num_ecnecho_received = htonl(tcpiterator->second.stats.num_ecnecho_received);
		tcpiterator->second.stats.num_cwr_sent = htonl(tcpiterator->second.stats.num_cwr_sent);
		tcpiterator->second.stats.num_cwr_received = htonl(tcpiterator->second.stats.num_cwr_received);
		tcpiterator->second.stats.num_frag_sent = htonl(tcpiterator->second.stats.num_frag_sent);
		tcpiterator->second.stats.num_frag_received = htonl(tcpiterator->second.stats.num_frag_received);
		tcpiterator->second.stats.num_dontfrag_sent = htonl(tcpiterator->second.stats.num_dontfrag_sent);
		tcpiterator->second.stats.num_dontfrag_received = htonl(tcpiterator->second.stats.num_dontfrag_received);
		tcpiterator->second.stats.local_min_win = htons(tcpiterator->second.stats.local_min_win);
		tcpiterator->second.stats.remote_min_win = htons(tcpiterator->second.stats.remote_min_win);
		tcpiterator->second.stats.local_ave_win = htons(tcpiterator->second.stats.local_ave_win);
		tcpiterator->second.stats.remote_ave_win = htons(tcpiterator->second.stats.remote_ave_win);
		tcpiterator->second.stats.local_max_win = htons(tcpiterator->second.stats.local_max_win);
		tcpiterator->second.stats.remote_max_win = htons(tcpiterator->second.stats.remote_max_win);
		tcpiterator->second.stats.local_min_ttl = htonl(tcpiterator->second.stats.local_min_ttl);
		tcpiterator->second.stats.local_max_ttl = htonl(tcpiterator->second.stats.local_max_ttl);
		tcpiterator->second.stats.remote_min_ttl = htonl(tcpiterator->second.stats.remote_min_ttl);
		tcpiterator->second.stats.remote_max_ttl = htonl(tcpiterator->second.stats.remote_max_ttl);
		tcpiterator->second.stats.num_retrans_sent = htonl(tcpiterator->second.stats.num_retrans_sent);
		tcpiterator->second.stats.num_retrans_received = htonl(tcpiterator->second.stats.num_retrans_received);
		tcpiterator->second.stats.bytes_retrans_sent = htonl(tcpiterator->second.stats.bytes_retrans_sent);
		tcpiterator->second.stats.bytes_retrans_received = htonl(tcpiterator->second.stats.bytes_retrans_received);
		tcpiterator->second.stats.num_inactivity_periods = htonl(tcpiterator->second.stats.num_inactivity_periods);
		tcpiterator->second.stats.min_rtt.tv_sec = htonl(tcpiterator->second.stats.min_rtt.tv_sec);
		tcpiterator->second.stats.min_rtt.tv_usec = htonl(tcpiterator->second.stats.min_rtt.tv_usec);
		tcpiterator->second.stats.max_rtt.tv_sec = htonl(tcpiterator->second.stats.max_rtt.tv_sec);
		tcpiterator->second.stats.max_rtt.tv_usec = htonl(tcpiterator->second.stats.max_rtt.tv_usec);
		tcpiterator->second.stats.ave_rtt.tv_sec = htonl(tcpiterator->second.stats.ave_rtt.tv_sec);
		tcpiterator->second.stats.ave_rtt.tv_usec = htonl(tcpiterator->second.stats.ave_rtt.tv_usec);
		tcpiterator->second.stats.syn_rtt.tv_sec = htonl(tcpiterator->second.stats.syn_rtt.tv_sec);
		tcpiterator->second.stats.syn_rtt.tv_usec = htonl(tcpiterator->second.stats.syn_rtt.tv_usec);
		tcpiterator->second.stats.num_in_order = htonl(tcpiterator->second.stats.num_in_order);
		tcpiterator->second.stats.num_out_order = htonl(tcpiterator->second.stats.num_out_order);
		tcpiterator->second.stats.local_mss = htonl(tcpiterator->second.stats.local_mss);
		tcpiterator->second.stats.remote_mss = htonl(tcpiterator->second.stats.remote_mss);
		tcpiterator->second.stats.drops = htonl(tcpiterator->second.stats.drops);


		old_TCP_Flows.insert(*tcpiterator);
		TCP_Flows.erase(tcpiterator);
	}

	// Iterate through TCP flows to find expired flows
	// MAYBE SHOULD BE do .. while
	tcpiterator = TCP_Flows.begin();
	while(tcpiterator != TCP_Flows.end()) {
		if(difftime(time(NULL), tcpiterator->second.time_last.tv_sec) > RETIRE_TIME) {
			// remove from list and insert into old list
			tcpiterator->second.stats.closure_method = IDLE_CLOSED;
			tcpiterator->second.stats.time_closed = tcpiterator->second.time_last;

			// But first, hton everything
			tcpiterator->second.stats.type = htonl(tcpiterator->second.stats.type);
			tcpiterator->second.stats.time_established.tv_sec = htonl(tcpiterator->second.stats.time_established.tv_sec);
			tcpiterator->second.stats.time_established.tv_usec = htonl(tcpiterator->second.stats.time_established.tv_usec);
			tcpiterator->second.stats.time_closed.tv_sec = htonl(tcpiterator->second.stats.time_closed.tv_sec);
			tcpiterator->second.stats.time_closed.tv_usec = htonl(tcpiterator->second.stats.time_closed.tv_usec);
			tcpiterator->second.stats.local_port = htons(tcpiterator->second.stats.local_port);
			tcpiterator->second.stats.remote_port = htons(tcpiterator->second.stats.remote_port);
			tcpiterator->second.stats.num_badtcpsum = htonl(tcpiterator->second.stats.num_badtcpsum);
			tcpiterator->second.stats.num_badipsum = htonl(tcpiterator->second.stats.num_badipsum);
			tcpiterator->second.stats.packets_sent = htonl(tcpiterator->second.stats.packets_sent);
			tcpiterator->second.stats.packets_received = htonl(tcpiterator->second.stats.packets_received);
			tcpiterator->second.stats.bytes_sent = htonl(tcpiterator->second.stats.bytes_sent);
			tcpiterator->second.stats.bytes_received = htonl(tcpiterator->second.stats.bytes_received);
			tcpiterator->second.stats.num_acks_sent = htonl(tcpiterator->second.stats.num_acks_sent);
			tcpiterator->second.stats.num_acks_received = htonl(tcpiterator->second.stats.num_acks_received);
			tcpiterator->second.stats.num_dup_acks_sent = htonl(tcpiterator->second.stats.num_dup_acks_sent);
			tcpiterator->second.stats.num_dup_acks_received = htonl(tcpiterator->second.stats.num_dup_acks_received);
			tcpiterator->second.stats.num_trip_acks_sent = htonl(tcpiterator->second.stats.num_trip_acks_sent);
			tcpiterator->second.stats.num_trip_acks_received = htonl(tcpiterator->second.stats.num_trip_acks_received);
			tcpiterator->second.stats.min_packet_size_sent = htons(tcpiterator->second.stats.min_packet_size_sent);
			tcpiterator->second.stats.min_packet_size_received = htons(tcpiterator->second.stats.min_packet_size_received);
			tcpiterator->second.stats.ave_packet_size_sent = htons(tcpiterator->second.stats.ave_packet_size_sent);
			tcpiterator->second.stats.ave_packet_size_received = htons(tcpiterator->second.stats.ave_packet_size_received);
			tcpiterator->second.stats.max_packet_size_sent = htons(tcpiterator->second.stats.max_packet_size_sent);
			tcpiterator->second.stats.max_packet_size_received = htons(tcpiterator->second.stats.max_packet_size_received);
			tcpiterator->second.stats.num_urg_sent = htonl(tcpiterator->second.stats.num_urg_sent);
			tcpiterator->second.stats.num_urg_received = htonl(tcpiterator->second.stats.num_urg_received);
			tcpiterator->second.stats.num_push_sent = htonl(tcpiterator->second.stats.num_push_sent);
			tcpiterator->second.stats.num_push_received = htonl(tcpiterator->second.stats.num_push_received);
			tcpiterator->second.stats.num_ecnecho_sent = htonl(tcpiterator->second.stats.num_ecnecho_sent);
			tcpiterator->second.stats.num_ecnecho_received = htonl(tcpiterator->second.stats.num_ecnecho_received);
			tcpiterator->second.stats.num_cwr_sent = htonl(tcpiterator->second.stats.num_cwr_sent);
			tcpiterator->second.stats.num_cwr_received = htonl(tcpiterator->second.stats.num_cwr_received);
			tcpiterator->second.stats.num_frag_sent = htonl(tcpiterator->second.stats.num_frag_sent);
			tcpiterator->second.stats.num_frag_received = htonl(tcpiterator->second.stats.num_frag_received);
			tcpiterator->second.stats.num_dontfrag_sent = htonl(tcpiterator->second.stats.num_dontfrag_sent);
			tcpiterator->second.stats.num_dontfrag_received = htonl(tcpiterator->second.stats.num_dontfrag_received);
			tcpiterator->second.stats.local_min_win = htons(tcpiterator->second.stats.local_min_win);
			tcpiterator->second.stats.remote_min_win = htons(tcpiterator->second.stats.remote_min_win);
			tcpiterator->second.stats.local_ave_win = htons(tcpiterator->second.stats.local_ave_win);
			tcpiterator->second.stats.remote_ave_win = htons(tcpiterator->second.stats.remote_ave_win);
			tcpiterator->second.stats.local_max_win = htons(tcpiterator->second.stats.local_max_win);
			tcpiterator->second.stats.remote_max_win = htons(tcpiterator->second.stats.remote_max_win);
			tcpiterator->second.stats.local_min_ttl = htonl(tcpiterator->second.stats.local_min_ttl);
			tcpiterator->second.stats.local_max_ttl = htonl(tcpiterator->second.stats.local_max_ttl);
			tcpiterator->second.stats.remote_min_ttl = htonl(tcpiterator->second.stats.remote_min_ttl);
			tcpiterator->second.stats.remote_max_ttl = htonl(tcpiterator->second.stats.remote_max_ttl);
			tcpiterator->second.stats.num_retrans_sent = htonl(tcpiterator->second.stats.num_retrans_sent);
			tcpiterator->second.stats.num_retrans_received = htonl(tcpiterator->second.stats.num_retrans_received);
			tcpiterator->second.stats.bytes_retrans_sent = htonl(tcpiterator->second.stats.bytes_retrans_sent);
			tcpiterator->second.stats.bytes_retrans_received = htonl(tcpiterator->second.stats.bytes_retrans_received);
			tcpiterator->second.stats.num_inactivity_periods = htonl(tcpiterator->second.stats.num_inactivity_periods);
			tcpiterator->second.stats.min_rtt.tv_sec = htonl(tcpiterator->second.stats.min_rtt.tv_sec);
			tcpiterator->second.stats.min_rtt.tv_usec = htonl(tcpiterator->second.stats.min_rtt.tv_usec);
			tcpiterator->second.stats.max_rtt.tv_sec = htonl(tcpiterator->second.stats.max_rtt.tv_sec);
			tcpiterator->second.stats.max_rtt.tv_usec = htonl(tcpiterator->second.stats.max_rtt.tv_usec);
			tcpiterator->second.stats.ave_rtt.tv_sec = htonl(tcpiterator->second.stats.ave_rtt.tv_sec);
			tcpiterator->second.stats.ave_rtt.tv_usec = htonl(tcpiterator->second.stats.ave_rtt.tv_usec);
			tcpiterator->second.stats.syn_rtt.tv_sec = htonl(tcpiterator->second.stats.syn_rtt.tv_sec);
			tcpiterator->second.stats.syn_rtt.tv_usec = htonl(tcpiterator->second.stats.syn_rtt.tv_usec);
			tcpiterator->second.stats.num_in_order = htonl(tcpiterator->second.stats.num_in_order);
			tcpiterator->second.stats.num_out_order = htonl(tcpiterator->second.stats.num_out_order);
			tcpiterator->second.stats.local_mss = htonl(tcpiterator->second.stats.local_mss);
			tcpiterator->second.stats.remote_mss = htonl(tcpiterator->second.stats.remote_mss);
			tcpiterator->second.stats.drops = htonl(tcpiterator->second.stats.drops);


			old_TCP_Flows.insert(*tcpiterator);
			TCP_Flows.erase(tcpiterator);
			tcpiterator = TCP_Flows.begin();
		}
		else {
			tcpiterator++;
		}
	}
*/
}

// UDP Packet (User Datagram Protocol)
void NETIUDP(Packet *p) {
/*
	struct Flow_Key fk;
	map<struct Flow_Key, class UDP_Flow, fkcompare>::iterator udpiterator;

	NETIIP_struct ip_struct;
	NETIIP(p, &ip_struct);

	if(p->udph == NULL) {
		// need to do some kind of PacketError thing (count as dropped???)
		return;
	}

	// Don't want to capture Loopback packets
	if(isLoopback(ip_struct.src_ip) || isLoopback(ip_struct.dest_ip)) {
		return;
	}

	// Place all variables into UDP_Flow
	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
		fk.my_ip = ip_struct.src_ip;
		fk.remote_ip = ip_struct.dest_ip;
		fk.my_port = ip_struct.src_port;
		fk.remote_port = ip_struct.dest_port;
	}
	else {
		fk.my_ip = ip_struct.dest_ip;
		fk.remote_ip = ip_struct.src_ip;
		fk.my_port = ip_struct.dest_port;
		fk.remote_port = ip_struct.src_port;
	}

	if(UDP_Flows.count(fk)) {
		// insert new data to existing flow

		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Sender (Local)

			if(p->dsize > UDP_Flows[fk].stats.max_packet_size_sent) {
				UDP_Flows[fk].stats.max_packet_size_sent = p->dsize;
			}
			else if(p->dsize < UDP_Flows[fk].stats.min_packet_size_sent) {
				UDP_Flows[fk].stats.min_packet_size_sent = p->dsize;
			}
		}
		else {
			// Receiver (Remote)

			if(p->dsize > UDP_Flows[fk].stats.max_packet_size_received) {
				UDP_Flows[fk].stats.max_packet_size_received = p->dsize;
			}
			else if(p->dsize < UDP_Flows[fk].stats.min_packet_size_received) {
				UDP_Flows[fk].stats.min_packet_size_received = p->dsize;
			}
		}
	}
	else {
		// insert new flow
		// Map Stuff
		// Send fk.remote_ip to NETIMap
		string ipdata(inet_ntoa(fk.remote_ip));
		if(!isPrivate(ipdata)) {
			sendto(netimapfd, ipdata.c_str(), strlen(ipdata.c_str()),0, (sockaddr *)&netimap_addr, sizeof(netimap_addr));
		}

		if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
			// Sender (Local)

			UDP_Flows[fk].stats.max_packet_size_sent = p->dsize;
			UDP_Flows[fk].stats.min_packet_size_sent = p->dsize;
		}
		else {
			// Receiver (Remote)

			UDP_Flows[fk].stats.max_packet_size_received = p->dsize;
			UDP_Flows[fk].stats.min_packet_size_received = p->dsize;
		}


		// LOW privacy
		if(privacylevel == 0) {
			UDP_Flows[fk].stats.local_ip = fk.my_ip;
			UDP_Flows[fk].stats.remote_ip = fk.remote_ip;
		}
		// HIGH privacy
		else if(privacylevel == 2) {
			UDP_Flows[fk].stats.local_ip.s_addr = 0;
			UDP_Flows[fk].stats.remote_ip.s_addr = 0;
		}
		// MEDIUM (default) privacy
		else {
			// Only keep network part of address
			if(isBroadcastIP(fk.my_ip) == 1) {
				UDP_Flows[fk].stats.local_ip = fk.my_ip;
			}
			else {
				UDP_Flows[fk].stats.local_ip.s_addr = (fk.my_ip.s_addr & pv.netmask);
			}

			if(isBroadcastIP(fk.remote_ip) == 1) {
				UDP_Flows[fk].stats.remote_ip = fk.remote_ip;
			}
			else {
				UDP_Flows[fk].stats.remote_ip.s_addr = (fk.remote_ip.s_addr & pv.netmask);
			}
		}
		UDP_Flows[fk].stats.local_port = fk.my_port;
		UDP_Flows[fk].stats.remote_port = fk.remote_port;
		UDP_Flows[fk].stats.time_first_packet = ip_struct.ts;
	}

	// Check UDP Checksum
	if(p->csum_flags & CSE_UDP) {
		UDP_Flows[fk].stats.num_badudpsum++;
	}

	// Check IP Checksum
	if(!ip_struct.checksumcorrect) {
		UDP_Flows[fk].stats.num_badipsum++;
	}

	UDP_Flows[fk].stats.time_last_packet = ip_struct.ts;

	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
		// Sender (Local)

		// Check for Fragmentation
		if(ip_struct.frag) {
			UDP_Flows[fk].stats.num_frag_sent++;
		}

		// Check the Don't Fragment Flag
		if(ip_struct.df) {
			UDP_Flows[fk].stats.num_dontfrag_sent++;
		}

		UDP_Flows[fk].stats.num_packets_sent++;

		UDP_Flows[fk].stats.ave_packet_size_sent = ((UDP_Flows[fk].stats.ave_packet_size_sent * (UDP_Flows[fk].stats.num_packets_sent - 1)) + p->dsize) / UDP_Flows[fk].stats.num_packets_sent;

	}
	else {
		// Receiver (Remote)

		// Check for Fragmentation
		if(ip_struct.frag) {
			UDP_Flows[fk].stats.num_frag_received++;
		}

		// Check the Don't Fragment Flag
		if(ip_struct.df) {
			UDP_Flows[fk].stats.num_dontfrag_received++;
		}

		UDP_Flows[fk].stats.num_packets_received++;

		UDP_Flows[fk].stats.ave_packet_size_received = ((UDP_Flows[fk].stats.ave_packet_size_received * (UDP_Flows[fk].stats.num_packets_received - 1)) + p->dsize) / UDP_Flows[fk].stats.num_packets_received;

	}

	// Iterate through UDP flows to find expired flows
	udpiterator = UDP_Flows.begin();
	while(udpiterator != UDP_Flows.end()) {
		if(difftime(time(NULL), udpiterator->second.stats.time_last_packet.tv_sec) > RETIRE_TIME) {
			// remove from list and insert into old list

			// But first, hton everything
			udpiterator->second.stats.type = htonl(udpiterator->second.stats.type);
			udpiterator->second.stats.local_port = htons(udpiterator->second.stats.local_port);
			udpiterator->second.stats.remote_port = htons(udpiterator->second.stats.remote_port);
			udpiterator->second.stats.num_badudpsum = htonl(udpiterator->second.stats.num_badudpsum);
			udpiterator->second.stats.num_badipsum = htonl(udpiterator->second.stats.num_badipsum);
			udpiterator->second.stats.num_packets_sent = htonl(udpiterator->second.stats.num_packets_sent);
			udpiterator->second.stats.num_packets_received = htonl(udpiterator->second.stats.num_packets_received);
			udpiterator->second.stats.num_bytes_sent = htonl(udpiterator->second.stats.num_bytes_sent);
			udpiterator->second.stats.num_bytes_received = htonl(udpiterator->second.stats.num_bytes_received);
			udpiterator->second.stats.num_frag_sent = htonl(udpiterator->second.stats.num_frag_sent);
			udpiterator->second.stats.num_frag_received = htonl(udpiterator->second.stats.num_frag_received);
			udpiterator->second.stats.num_dontfrag_sent = htonl(udpiterator->second.stats.num_dontfrag_sent);
			udpiterator->second.stats.num_dontfrag_received = htonl(udpiterator->second.stats.num_dontfrag_received);
			udpiterator->second.stats.min_packet_size_sent = htons(udpiterator->second.stats.min_packet_size_sent);
			udpiterator->second.stats.min_packet_size_received = htons(udpiterator->second.stats.min_packet_size_received);
			udpiterator->second.stats.ave_packet_size_sent = htons(udpiterator->second.stats.ave_packet_size_sent);
			udpiterator->second.stats.ave_packet_size_received = htons(udpiterator->second.stats.ave_packet_size_received);
			udpiterator->second.stats.max_packet_size_sent = htons(udpiterator->second.stats.max_packet_size_sent);
			udpiterator->second.stats.max_packet_size_received = htons(udpiterator->second.stats.max_packet_size_received);
			udpiterator->second.stats.time_first_packet.tv_sec = htonl(udpiterator->second.stats.time_first_packet.tv_sec);
			udpiterator->second.stats.time_first_packet.tv_usec = htonl(udpiterator->second.stats.time_first_packet.tv_usec);
			udpiterator->second.stats.time_last_packet.tv_sec = htonl(udpiterator->second.stats.time_last_packet.tv_sec);
			udpiterator->second.stats.time_last_packet.tv_usec = htonl(udpiterator->second.stats.time_last_packet.tv_usec);
			udpiterator->second.stats.drops = htonl(udpiterator->second.stats.drops);


			old_UDP_Flows.insert(*udpiterator);
			UDP_Flows.erase(udpiterator);
			udpiterator = UDP_Flows.begin();
		}
		else {
			udpiterator++;
		}
	}
*/
}

// ICMP Packet (Internet Control Message Protocol)
void NETIICMP(Packet *p) {
/*
	struct Flow_Key_NoPorts fknp;
	map<struct Flow_Key_NoPorts, class ICMP_Flow, fkcompare_noports>::iterator icmpiterator;

	NETIIP_struct ip_struct;
	NETIIP(p, &ip_struct);

	if(p->icmph == NULL) {
		// need to do some kind of PacketError thing (count as dropped???)
		return;
	}

	// Don't want to capture Loopback packets
	if(isLoopback(ip_struct.src_ip) || isLoopback(ip_struct.dest_ip)) {
		return;
	}

	// Place all variables into ICMP_Flow
	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
		fknp.my_ip = ip_struct.src_ip;
		fknp.remote_ip = ip_struct.dest_ip;
	}
	else {
		fknp.my_ip = ip_struct.dest_ip;
		fknp.remote_ip = ip_struct.src_ip;
	}

	if(ICMP_Flows.count(fknp)) {
		// insert new data to existing flow
	}
	else {
		// insert new flow

		// Map Stuff
		// Send fknp.remote_ip to NETIMap
		string ipdata(inet_ntoa(fknp.remote_ip));
		if(!isPrivate(ipdata)) {
			sendto(netimapfd, ipdata.c_str(), strlen(ipdata.c_str()),0, (sockaddr *)&netimap_addr, sizeof(netimap_addr));
		}

		// LOW privacy
		if(privacylevel == 0) {
			ICMP_Flows[fknp].stats.local_ip = fknp.my_ip;
			ICMP_Flows[fknp].stats.remote_ip = fknp.remote_ip;
		}
		// HIGH privacy
		else if(privacylevel == 2) {
			ICMP_Flows[fknp].stats.local_ip.s_addr = 0;
			ICMP_Flows[fknp].stats.remote_ip.s_addr = 0;
		}
		// MEDIUM (default)
		else {
			// Only keep network part of address
			if(isBroadcastIP(fknp.my_ip) == 1) {
				ICMP_Flows[fknp].stats.local_ip = fknp.my_ip;
			}
			else {
				ICMP_Flows[fknp].stats.local_ip.s_addr = (fknp.my_ip.s_addr & pv.netmask);
			}

			if(isBroadcastIP(fknp.remote_ip) == 1) {
				ICMP_Flows[fknp].stats.remote_ip = fknp.remote_ip;
			}
			else {
				ICMP_Flows[fknp].stats.remote_ip.s_addr = (fknp.remote_ip.s_addr & pv.netmask);
			}
		}

		// ICMP Type
		ICMP_Flows[fknp].stats.icmp_type = p->icmph->type;

		// ICMP Code
		ICMP_Flows[fknp].stats.icmp_code = p->icmph->code;

		ICMP_Flows[fknp].stats.time_first_packet = ip_struct.ts;
	}

	// Check ICMP Checksum
	if(p->csum_flags & CSE_ICMP) {
		ICMP_Flows[fknp].stats.num_badicmpsum++;
	}

	// Check IP Checksum
	if(!ip_struct.checksumcorrect) {
		ICMP_Flows[fknp].stats.num_badipsum++;
	}

	ICMP_Flows[fknp].stats.time_last_packet = ip_struct.ts;

	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
		// Sender (Local)

		// Check for Fragmentation
		if(ip_struct.frag) {
			ICMP_Flows[fknp].stats.num_frag_sent++;
		}

		// Check the Don't Fragment Flag
		if(ip_struct.df) {
			ICMP_Flows[fknp].stats.num_dontfrag_sent++;
		}
	}
	else {
		// Receiver (Remote)

		// Check for Fragmentation
		if(ip_struct.frag) {
			ICMP_Flows[fknp].stats.num_frag_received++;
		}

		// Check the Don't Fragment Flag
		if(ip_struct.df) {
			ICMP_Flows[fknp].stats.num_dontfrag_received++;
		}
	}

	// Iterate through ICMP flows to find expired flows
	icmpiterator = ICMP_Flows.begin();
	while(icmpiterator != ICMP_Flows.end()) {
		if(difftime(time(NULL), icmpiterator->second.stats.time_last_packet.tv_sec) > RETIRE_TIME) {
			// remove from list and insert into old list

			// But first, hton everything
			icmpiterator->second.stats.type = htonl(icmpiterator->second.stats.type);
			icmpiterator->second.stats.UNUSED = htons(icmpiterator->second.stats.UNUSED);
			icmpiterator->second.stats.num_badicmpsum = htonl(icmpiterator->second.stats.num_badicmpsum);
			icmpiterator->second.stats.num_badipsum = htonl(icmpiterator->second.stats.num_badipsum);
			icmpiterator->second.stats.num_frag_sent = htonl(icmpiterator->second.stats.num_frag_sent);
			icmpiterator->second.stats.num_frag_received = htonl(icmpiterator->second.stats.num_frag_received);
			icmpiterator->second.stats.num_dontfrag_sent = htonl(icmpiterator->second.stats.num_dontfrag_sent);
			icmpiterator->second.stats.num_dontfrag_received = htonl(icmpiterator->second.stats.num_dontfrag_received);
			icmpiterator->second.stats.time_first_packet.tv_sec = htonl(icmpiterator->second.stats.time_first_packet.tv_sec);
			icmpiterator->second.stats.time_first_packet.tv_usec = htonl(icmpiterator->second.stats.time_first_packet.tv_usec);
			icmpiterator->second.stats.time_last_packet.tv_sec = htonl(icmpiterator->second.stats.time_last_packet.tv_sec);
			icmpiterator->second.stats.time_last_packet.tv_usec = htonl(icmpiterator->second.stats.time_last_packet.tv_usec);
			icmpiterator->second.stats.drops = htonl(icmpiterator->second.stats.drops);


			old_ICMP_Flows.insert(*icmpiterator);
			ICMP_Flows.erase(icmpiterator);
			icmpiterator = ICMP_Flows.begin();
		}
		else {
			icmpiterator++;
		}
	}
*/
}

// IGMP Packet (Internet Group Management Protocol)
void NETIIGMP(Packet *p) {
/*
	class IGMP_Flow igmpflow;

	NETIIP_struct ip_struct;
	NETIIP(p, &ip_struct);

	if(p->igmph == NULL) {
		// need to do some kind of PacketError thing (count as dropped???)
		return;
	}

	// Don't want to capture Loopback packets
	if(isLoopback(ip_struct.src_ip) || isLoopback(ip_struct.dest_ip)) {
		return;
	}

	// Place all variables into IGMP_Flow
	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
		// Map Stuff
		// Send remote_ip to NETIMap
		string ipdata(inet_ntoa(ip_struct.dest_ip));
		if(!isPrivate(ipdata)) {
			sendto(netimapfd, ipdata.c_str(), strlen(ipdata.c_str()),0, (sockaddr *)&netimap_addr, sizeof(netimap_addr));
		}
	}
	else {
		// Map Stuff
		// Send remote_ip to NETIMap
		string ipdata(inet_ntoa(ip_struct.src_ip));
		if(!isPrivate(ipdata)) {
			sendto(netimapfd, ipdata.c_str(), strlen(ipdata.c_str()),0, (sockaddr *)&netimap_addr, sizeof(netimap_addr));
		}
	}

	// LOW privacy
	if(privacylevel == 0) {
		igmpflow.stats.src_ip = ip_struct.src_ip;
		igmpflow.stats.dest_ip = ip_struct.dest_ip;
		igmpflow.stats.mcast_ip = p->igmph->gaddr;
	}
	// HIGH privacy
	else if(privacylevel == 2) {
		igmpflow.stats.src_ip.s_addr = 0;
		igmpflow.stats.dest_ip.s_addr = 0;
		igmpflow.stats.mcast_ip.s_addr = 0;
	}
	// MEDIUM (default) privacy
	else {
		// Only keep network part of address
		if(isBroadcastIP(ip_struct.src_ip) == 1) {
			igmpflow.stats.src_ip = ip_struct.src_ip;
		}
		else {
			igmpflow.stats.src_ip.s_addr = (ip_struct.src_ip.s_addr & pv.netmask);
		}

		if(isBroadcastIP(ip_struct.dest_ip) == 1) {
			igmpflow.stats.dest_ip = ip_struct.dest_ip;
		}
		else {
			igmpflow.stats.dest_ip.s_addr = (ip_struct.dest_ip.s_addr & pv.netmask);
		}

		if(isBroadcastIP(p->igmph->gaddr) == 1) {
			igmpflow.stats.mcast_ip = p->igmph->gaddr;
		}
		else {
			igmpflow.stats.mcast_ip.s_addr = (p->igmph->gaddr.s_addr & pv.netmask);
		}
	}

	// IGMP Type
	igmpflow.stats.igmp_type = p->igmph->type;

	// IGMP Maximum Response Time
	igmpflow.stats.igmp_mrt = p->igmph->mrt;

	// Timestamp
	igmpflow.stats.time_of_packet = ip_struct.ts;

	// Check IGMP Checksum
	if(p->csum_flags & CSE_IGMP) {
		igmpflow.stats.flags |= 0x08;
	}

	// Check IP Checksum
	if(!ip_struct.checksumcorrect) {
		igmpflow.stats.flags |= 0x04;
	}

	// Check for Fragmentation
	if(ip_struct.frag) {
		igmpflow.stats.flags |= 0x02;
	}

	// Check the Don't Fragment Flag
	if(ip_struct.df) {
		igmpflow.stats.flags |= 0x01;
	}

	if(whichEqualIP(ip_struct.src_ip, ip_struct.dest_ip) == 1) {
		// Sender
		igmpflow.stats.flags |= 0x10;
	}
	else {
		// Receiver
	}

	// Add to old_IGMP_Flows (Since we have no real concept of an IGMP Flow)

	// But first, hton everything
	igmpflow.stats.type = htonl(igmpflow.stats.type);
	igmpflow.stats.time_of_packet.tv_sec = htonl(igmpflow.stats.time_of_packet.tv_sec);
	igmpflow.stats.time_of_packet.tv_usec = htonl(igmpflow.stats.time_of_packet.tv_usec);

	old_IGMP_Flows.push_back(igmpflow);
*/
}

void NETIOther(Packet *p) {
/*
	// Do IP Stuff?
	NETIIP_struct ip_struct;
	NETIIP(p, &ip_struct);
*/
}

// IP Packet (Internet Protocol)
void NETIIP(Packet *p, NETIIP_struct *ip_struct) {
/*
	if(p->iph == NULL) {
		return;				// IP header truncated
	}

	// Source IP Address
	ip_struct->src_ip = p->iph->ip_src;

	// Destination IP Address
	ip_struct->dest_ip = p->iph->ip_dst;

	if(p->iph->ip_proto == IPPROTO_TCP || p->iph->ip_proto == IPPROTO_UDP) {
		ip_struct->src_port = p->sp;	// Source Port
		ip_struct->dest_port = p->dp;	// Destination Port
	}
	else {
		ip_struct->src_port = 0;	// Source Port
		ip_struct->dest_port = 0;	// Destination Port
	}

	// Timestamp
	ip_struct->ts = p->pkth->ts;

	// TTL
	ip_struct->ttl = p->iph->ip_ttl;

	if(p->df) {
		ip_struct->df = 1;			// Don't Fragment Set
	}
	else {
		ip_struct->df = 0;			// Don't Fragment Not Set
	}

	if(p->frag_flag) {
		ip_struct->frag = 1;			// Fragmented
	}
	else {
		ip_struct->frag = 0;			// Not Fragmented
	}

	if(p->csum_flags & CSE_IP) {
		ip_struct->checksumcorrect = 0;		// IP Checksum Incorrect
	}
	else {
		ip_struct->checksumcorrect = 1;		// IP Checksum Correct
	}


	// From PrintIPPkt and Print2ndHeader and PrintIPHeader and PrintIpOptions
	// Possible Additional Stats:
	p->iph->ip_tos				// TOS
	ntohs(p->iph->ip_id)			// ID
	if(p->rf)
		// Reserved Bit Set
	if(p->ip_option_count != 0) {
		// IP Options
		if(!p->ip_option_count || p->ip_option_count > 40) {
			// Bad
		}
		p->ip_option_count		// Number of IP Options
		for(i = 0; i < (int) p->ip_option_count; i++) {
			switch(p->ip_options[i].code) {
				case IPOPT_RR:	// RR
					break;
				case IPOPT_EOL:	// EOL
					break;
				case IPOPT_NOP:	// NOP
					break;
				case IPOPT_TS:	// TS
					break;
				case IPOPT_SECURITY:	// SEC
					break;
				case IPOPT_LSRR:
				case IPOPT_LSRR_E:	// LSRR
					break;
				case IPOPT_SATID:	// SID
					break;
				case IPOPT_SSRR:	// SSRR
					break;
				case IPOPT_RTRALT:	// RTRALT
					break;
				default:
					opt = p->ip_options[i].code
					if(p->ip_options[i].len) {
						for(j = 0; j < p->ip_options[i].len; j++) {
							p->ip_options[i].data[j]
						}
					}
					break;
			}
		}
	}
	if(p->frag_flag) {
		// Fragment Info
		ntohs(p->iph->ip_len) - (IP_HLEN(p->iph) << 2	// Frag Size
	}
	// End From PrintIPPkt and Print2ndHeader and PrintIPHeader and PrintIpOptions
*/
}

double htond(double d) {
	unsigned int *p;
	unsigned int *p2;
	double toBeReturned;
	p = (unsigned int *)&d;
	p2 = (unsigned int *)&toBeReturned;
	if(p[0] != htonl(p[0]) || p[1] != htonl(p[1])) {
		p2[0] = htonl(p[1]);
		p2[1] = htonl(p[0]);
		return toBeReturned;
	}
	else {
		return d;
	}
}

/*
 * Returns 1 if the src IP is mine,
 * 0 if the dest IP is mine, -1 on error.
 */
int whichEqualIP(struct in_addr src, struct in_addr dest)
{
	if_info_t *dev;
	if_addr_t *addrs;

	if(strcasecmp(pv.interface, "any") != 0) {
		for(dev = pv.interface_list; dev != NULL; dev = dev->next) {
			if(strcasecmp(dev->name, pv.interface) == 0) {
				break;
			}
		}
		if(dev == NULL) {
			return -1;
		}
		if(dev->addrs == NULL) {
			return -1;
		}
		for(addrs = dev->addrs; addrs != NULL; addrs = addrs->next) {
			if(src.s_addr == addrs->ip.s_addr) {
				return 1;
			}
			else if(dest.s_addr == addrs->ip.s_addr) {
				return 0;
			}
		}
	}
	else {
		for(dev = pv.interface_list; dev != NULL; dev = dev->next) {
			for(addrs = dev->addrs; addrs != NULL; addrs = addrs->next) {
				if(src.s_addr == addrs->ip.s_addr) {
					return 1;
				}
				else if(dest.s_addr == addrs->ip.s_addr) {
					return 0;
				}
			}
		}
	}
	return -1;
}

/*
 * Returns 1 if the given in_addr represents a
 * broadcast address, 0 otherwise
 */
int isBroadcastIP(struct in_addr in)
{
	in_addr_t i = ntohl(in.s_addr);
	if((i & 0x000000ff) == 0x000000ff) {
		return 1;
	}
	else {
		return 0;
	}
}

int isPrivate(string address)
{
	int len = strlen(address.c_str());
	if(len >= 3) {
		if(!strncmp(address.c_str(), "10.", 3)) {
			return 1;
		}
		else if(len >= 7) {
			if(!strncmp(address.c_str(), "192.168.", 7)) {
				return 1;
			}
			else if(!strncmp(address.c_str(), "172.", 4)) {
				if(!strncmp(address.c_str(), "172.16.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.17.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.18.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.19.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.20.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.21.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.22.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.23.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.24.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.25.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.26.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.27.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.28.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.29.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.30.", 7)) {
					return 1;
				}
				else if(!strncmp(address.c_str(), "172.31.", 7)) {
					return 1;
				}
			}
			else if(len >= 9) {
				if(!strncmp(address.c_str(), "127.0.0.1", 9)) {
					return 1;
				}
			}
			else if(len >= 14) {
				if(!strncmp(address.c_str(), NETGEO_IP, 14)) {
					return 1;
				}
			}
		}
	}
	return 0;
}

int isLoopback(struct in_addr in)
{
	if(in.s_addr == htonl(INADDR_LOOPBACK)) {
		return 1;
	}
	else {
		return 0;
	}
}

