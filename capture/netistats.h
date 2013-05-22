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

#ifndef NETI_STATS_H
#define NETI_STATS_H

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list>
#include <map>
#include "neti.h"

using namespace std;

#define NETI_NEW_USER 557557557
#define NETI_TCP_FLOW 2
#define NETI_UDP_FLOW 3
#define NETI_ICMP_FLOW 4
#define NETI_IGMP_FLOW 5

#define NETI_SENDER 1
#define NETI_RECEIVER 2

// Closure Methods
#define FIN_SENT 10
#define FIN_RECEIVED 11
#define RST_SENT 12
#define RST_RECEIVED 13
#define IDLE_CLOSED 14

// Establishment Methods
#define SYN_SENT 20
#define SYN_RECEIVED 21

typedef struct _NETIIP_struct {
	struct in_addr src_ip;
	struct in_addr dest_ip;
	uint16_t src_port;
	uint16_t dest_port;
	struct timeval ts;
	uint8_t ttl;
	int df;
	int frag;
	int checksumcorrect;
} NETIIP_struct;

void NETITCP(Packet *p);
void NETIUDP(Packet *p);
void NETIICMP(Packet *p);
void NETIIGMP(Packet *p);
void NETIOther(Packet *p);
void NETIIP(Packet *p, NETIIP_struct *ip_struct);

struct Flow_Key {
	struct in_addr my_ip;
	struct in_addr remote_ip;
	uint16_t my_port;
	uint16_t remote_port;
};

struct Flow_Key_NoPorts {
	struct in_addr my_ip;
	struct in_addr remote_ip;
};

struct fkcompare {
	bool operator()(const struct Flow_Key f1, const struct Flow_Key f2) const {
		if(f1.my_ip.s_addr < f2.my_ip.s_addr)
			return 1;
		else {
			if(f1.my_ip.s_addr > f2.my_ip.s_addr)
				return 0;
			else {
				if(f1.remote_ip.s_addr < f2.remote_ip.s_addr)
					return 1;
				else {
					if(f1.remote_ip.s_addr > f2.remote_ip.s_addr)
						return 0;
					else {
						if(f1.my_port < f2.my_port)
							return 1;
						else {
							if(f1.my_port > f2.my_port)
								return 0;
							else {
								if(f1.remote_port < f2.remote_port)
									return 1;
								else
									return 0;
							}
						}
					}
				}
			}
		}
	}
};

struct fkcompare_noports {
	bool operator()(const struct Flow_Key_NoPorts f1, const struct Flow_Key_NoPorts f2) const {
		if(f1.my_ip.s_addr < f2.my_ip.s_addr)
			return 1;
		else {
			if(f1.my_ip.s_addr > f2.my_ip.s_addr)
				return 0;
			else {
				if(f1.remote_ip.s_addr < f2.remote_ip.s_addr)
					return 1;
				else {
					return 0;
				}
			}
		}
	}
};

struct TCP_Packet {
	unsigned long int seq_num;
	int length;
	struct timeval xmissiontime;
	bool acked;
	bool retrans;
	bool syn;
	bool mine;	// True if packet was sent by me (not received)
};

struct TCP_Stats {
	int32_t type;
	struct in_addr dest_ip;
	struct in_addr src_ip;
	struct timeval time_established;
	struct timeval time_closed;
	uint16_t src_port;
	uint16_t dest_port;
	int32_t num_badsum;		// Number of bad checksums
	int32_t num_badipsum;	// Number of bad IP header checksums
	int32_t packets_sent;
	int32_t packets_received;
	int32_t bytes_sent;
	int32_t bytes_received;
	int32_t num_acks;
	int32_t num_dup_acks;
	int32_t num_trip_acks;
	int32_t num_urg;
	int32_t num_push;
	int32_t num_ecnecho;
	int32_t num_cwr;
	int32_t sender_SACK_perm;
	int32_t receiver_SACK_perm;
	int32_t num_frag;
	int32_t num_dontfrag;
	int32_t sender_max_win;
	int32_t sender_ave_win;
	int32_t sender_min_win;
	int32_t receiver_max_win;
	int32_t receiver_ave_win;
	int32_t receiver_min_win;
	int32_t sender_min_ttl;
	int32_t sender_max_ttl;
	int32_t receiver_min_ttl;
	int32_t receiver_max_ttl;
	int32_t num_retrans;
	int32_t bytes_retrans;
	int32_t num_timeouts;
	struct timeval min_rtt;
	struct timeval max_rtt;
	struct timeval ave_rtt;
	int32_t idle_close;
	int32_t rst_close;
	int32_t num_in_order;
	int32_t num_out_order;
	int32_t sender_mss;		// Maximum segment size
	int32_t receiver_mss;		// Maximum segment size

	// The following stats are not being collected yet until we figure out how to do so
	//int num_cwnd_reduc;
	//int num_cwnd_inc;
	//int num_ss;
	//struct timeval small_interarrival;
	//struct timeval largest_interarrival;
	// End of stats for TCP
};

struct TCP_Stats_v2 {
	int32_t type;
	struct in_addr remote_ip;
	struct in_addr local_ip;
	struct timeval time_established;
	struct timeval time_closed;
	uint16_t local_port;
	uint16_t remote_port;
	int32_t num_badtcpsum;		// Number of bad TCP checksums
	int32_t num_badipsum;		// Number of bad IP header checksums
	int32_t packets_sent;
	int32_t packets_received;
	int32_t bytes_sent;
	int32_t bytes_received;
	int32_t num_acks_sent;
	int32_t num_acks_received;
	int32_t num_dup_acks_sent;
	int32_t num_dup_acks_received;
	int32_t num_trip_acks_sent;
	int32_t num_trip_acks_received;
	uint16_t min_packet_size_sent;
	uint16_t min_packet_size_received;
	uint16_t ave_packet_size_sent;
	uint16_t ave_packet_size_received;
	uint16_t max_packet_size_sent;
	uint16_t max_packet_size_received;
	int32_t num_urg_sent;
	int32_t num_urg_received;
	int32_t num_push_sent;
	int32_t num_push_received;
	int32_t num_ecnecho_sent;
	int32_t num_ecnecho_received;
	int32_t num_cwr_sent;
	int32_t num_cwr_received;
	int32_t num_frag_sent;
	int32_t num_frag_received;
	int32_t num_dontfrag_sent;
	int32_t num_dontfrag_received;
	uint16_t local_min_win;
	uint16_t remote_min_win;
	uint16_t local_ave_win;
	uint16_t remote_ave_win;
	uint16_t local_max_win;
	uint16_t remote_max_win;
	uint8_t local_win_scale;
	uint8_t remote_win_scale;
	uint16_t UNUSED;
	uint8_t local_min_ttl;
	uint8_t local_max_ttl;
	uint8_t remote_min_ttl;
	uint8_t remote_max_ttl;
	int32_t num_retrans_sent;
	int32_t num_retrans_received;
	int32_t bytes_retrans_sent;
	int32_t bytes_retrans_received;
	int32_t num_inactivity_periods;
	struct timeval min_rtt;
	struct timeval max_rtt;
	struct timeval ave_rtt;
	struct timeval syn_rtt;
	int32_t num_in_order;
	int32_t num_out_order;
	int32_t local_mss;		// Maximum segment size
	int32_t remote_mss;		// Maximum segment size
	uint8_t con_estb_method;	// Connection Establishment Method
	uint8_t closure_method;		// Connection Closure Method
	uint8_t local_SACK_perm;
	uint8_t remote_SACK_perm;
	int32_t drops;			// Possibility of Dropped Packets?

	// The following stats are not being collected yet until we figure out how to do so
	//int num_cwnd_reduc;
	//int num_cwnd_inc;
	//int num_ss;
	//struct timeval small_interarrival;
	//struct timeval largest_interarrival;
	// End of stats for TCP
};

struct UDP_Stats {
	int32_t type;
	struct in_addr dest_ip;
	struct in_addr src_ip;
	uint16_t src_port;
	uint16_t dest_port;
	int32_t num_badsum;		// Number of bad checksums
	int32_t num_badipsum;	// Number of bad IP header checksums
	int32_t num_packets;
	int32_t num_frag;
	int32_t num_dontfrag;
	int32_t ave_packet_size;
	int32_t min_packet_size;
	int32_t max_packet_size;
	struct timeval time_first_packet;
	struct timeval time_last_packet;
};

struct UDP_Stats_v2 {
	int32_t type;
	struct in_addr remote_ip;
	struct in_addr local_ip;
	uint16_t local_port;
	uint16_t remote_port;
	int32_t num_badudpsum;		// Number of bad UDP checksums
	int32_t num_badipsum;		// Number of bad IP header checksums
	int32_t num_packets_sent;
	int32_t num_packets_received;
	int32_t num_bytes_sent;
	int32_t num_bytes_received;
	int32_t num_frag_sent;
	int32_t num_frag_received;
	int32_t num_dontfrag_sent;
	int32_t num_dontfrag_received;
	uint16_t min_packet_size_sent;
	uint16_t min_packet_size_received;
	int16_t ave_packet_size_sent;
	int16_t ave_packet_size_received;
	uint16_t max_packet_size_sent;
	uint16_t max_packet_size_received;
	struct timeval time_first_packet;
	struct timeval time_last_packet;
	int32_t drops;			// Possibility of Dropped Packets?
};

struct ICMP_Stats {
	int32_t type;
	struct in_addr dest_ip;
	struct in_addr src_ip;
	int32_t icmp_type;
	int32_t code;
	int32_t num_badsum;
	int32_t num_badipsum;
	int32_t num_frag;
	int32_t num_dontfrag;
//	int identifier;
//	int seq_num;
//	int data_size;
};

struct ICMP_Stats_v2 {
	int32_t type;
	struct in_addr remote_ip;
	struct in_addr local_ip;
	uint8_t icmp_type;
	uint8_t icmp_code;
	int16_t UNUSED;
	int32_t num_badicmpsum;
	int32_t num_badipsum;
	int32_t num_frag_sent;
	int32_t num_frag_received;
	int32_t num_dontfrag_sent;
	int32_t num_dontfrag_received;
	struct timeval time_first_packet;
	struct timeval time_last_packet;
	int32_t drops;			// Possibility of Dropped Packets?
};

struct IGMP_Stats {
	int32_t type;
	struct in_addr dest_ip;
	struct in_addr src_ip;
	struct in_addr mcast_ip;
	int32_t version;
	int32_t igmp_type;
	int32_t num_badsum;
	int32_t num_badipsum;
	int32_t num_packets;
	int32_t num_frag;
	int32_t num_dontfrag;
	int32_t max_response_time;
	struct timeval time_first_packet;
	struct timeval time_last_packet;
};

struct IGMP_Stats_v2 {
	int32_t type;
	struct in_addr dest_ip;
	struct in_addr src_ip;
	struct in_addr mcast_ip;
	uint8_t igmp_type;
	uint8_t igmp_mrt;
	uint8_t UNUSED;
	uint8_t flags;
	struct timeval time_of_packet;
};

class TCP_Flow {
	public:
		struct TCP_Stats_v2 stats;
		
		// Helper statistics, not to be sent
		unsigned long int last_ack_num_sent;		// last ack number
		unsigned long int last_ack_num_recv;		// last ack number
		unsigned long int last_last_ack_num_sent;	// ack number before the last
		unsigned long int last_last_ack_num_recv;	// ack number before the last
		unsigned long int highest_seq_num_sent;		// sequence number high water mark
		unsigned long int highest_seq_num_recv;		// sequence number high water mark
		unsigned long int next_seq_num;			// next expected seq num to be received
		struct timeval time_last;
		struct timeval time_last_ack;			// used to calculate suspected timeouts
		int num_rtt;					// number of calculated RTT's, used to calculate average
		list<struct TCP_Packet> packets;		// linked list of packet info
		bool gotSyn;					// True if SYN packet has been seen
		struct timeval syntime;				// Time of the SYN packet (for SYN RTT calculation)
		bool synerr;					// True if error encountered calculating SYN RTT
		bool gotSynRtt;					// True if SYN RTT has been calculated

		// Constructor
		TCP_Flow(void) {
			stats.type = NETI_TCP_FLOW;
			stats.remote_ip.s_addr = 0;
			stats.local_ip.s_addr = 0;
			stats.time_established.tv_sec = 0;
			stats.time_established.tv_usec = 0;
			stats.time_closed.tv_sec = 0;
			stats.time_closed.tv_usec = 0;
			stats.local_port = 0;
			stats.remote_port = 0;
			stats.num_badtcpsum = 0;
			stats.num_badipsum = 0;
			stats.packets_sent = 0;
			stats.packets_received = 0;
			stats.bytes_sent = 0;
			stats.bytes_received = 0;
			stats.num_acks_sent = 0;
			stats.num_acks_received = 0;
			stats.num_dup_acks_sent = 0;
			stats.num_dup_acks_received = 0;
			stats.num_trip_acks_sent = 0;
			stats.num_trip_acks_received = 0;
			stats.min_packet_size_sent = 65535;
			stats.min_packet_size_received = 65535;
			stats.ave_packet_size_sent = 0;
			stats.ave_packet_size_received = 0;
			stats.max_packet_size_sent = 0;
			stats.max_packet_size_received = 0;
			stats.num_urg_sent = 0;
			stats.num_urg_received = 0;
			stats.num_push_sent = 0;
			stats.num_push_received = 0;
			stats.num_ecnecho_sent = 0;
			stats.num_ecnecho_received = 0;
			stats.num_cwr_sent = 0;
			stats.num_cwr_received = 0;
			stats.num_frag_sent = 0;
			stats.num_frag_received = 0;
			stats.num_dontfrag_sent = 0;
			stats.num_dontfrag_received = 0;
			stats.local_min_win = 65535;
			stats.remote_min_win = 65535;
			stats.local_ave_win = 0;
			stats.remote_ave_win = 0;
			stats.local_max_win = 0;
			stats.remote_max_win = 0;
			stats.local_win_scale = 0;
			stats.remote_win_scale = 0;
			stats.UNUSED = 0;
			stats.local_min_ttl = 255;
			stats.local_max_ttl = 0;
			stats.remote_min_ttl = 255;
			stats.remote_max_ttl = 0;
			stats.num_retrans_sent = 0;
			stats.num_retrans_received = 0;
			stats.bytes_retrans_sent = 0;
			stats.bytes_retrans_received = 0;
			stats.num_inactivity_periods = 0;
			stats.min_rtt.tv_sec  = 999999;
			stats.min_rtt.tv_usec = 999999;
			stats.max_rtt.tv_sec  = 0;
			stats.max_rtt.tv_usec = 0;
			stats.ave_rtt.tv_sec  = 0;
			stats.ave_rtt.tv_usec = 0;
			stats.syn_rtt.tv_sec  = 0;
			stats.syn_rtt.tv_usec = 0;
			stats.num_in_order = 0;
			stats.num_out_order = 0;
			stats.local_mss = 0;
			stats.remote_mss = 0;
			stats.con_estb_method = 0;
			stats.closure_method = 0;
			stats.local_SACK_perm = 0;
			stats.remote_SACK_perm = 0;
			stats.drops = 0;

			//stats.num_ss = 0;
			//stats.num_cwnd_reduc = 0;
			//stats.num_cwnd_inc = 0;
			//stats.small_interarrival.tv_sec = 999999;
			//stats.small_interarrival.tv_usec = 0;
			//stats.largest_interarrival.tv_sec = 0;
			//stats.largest_interarrival.tv_usec = 0;

			last_ack_num_sent = 0;
			last_ack_num_recv = 0;
			last_last_ack_num_sent = 1;
			last_last_ack_num_recv = 1;
			highest_seq_num_sent = 0;
			highest_seq_num_recv = 0;
			next_seq_num = 0;
			time_last.tv_sec = 0;
			time_last.tv_usec = 0;
			time_last_ack.tv_sec = 0;
			time_last_ack.tv_usec = 0;
			num_rtt = 0;
			gotSyn = false;
			syntime.tv_sec = 0;
			syntime.tv_usec = 0;
			synerr = false;
			gotSynRtt = false;
		}
		// insert important data into given buffer
		char * serialize(char *buf, int *left) {
			if(*left < sizeof(struct TCP_Stats_v2)) {
				return NULL;
			}
			memcpy(buf, &stats, sizeof(stats));
			buf += sizeof(stats);
			*left -= sizeof(stats);
			return buf;
		}
};

class UDP_Flow {
	public:
		struct UDP_Stats_v2 stats;
		UDP_Flow(void) {
			stats.type = NETI_UDP_FLOW;
			stats.remote_ip.s_addr = 0;
			stats.local_ip.s_addr = 0;
			stats.local_port = 0;
			stats.remote_port = 0;
			stats.num_badudpsum = 0;
			stats.num_badipsum = 0;
			stats.num_packets_sent = 0;
			stats.num_packets_received = 0;
			stats.num_bytes_sent = 0;
			stats.num_bytes_received = 0;
			stats.num_frag_sent = 0;
			stats.num_frag_received = 0;
			stats.num_dontfrag_sent = 0;
			stats.num_dontfrag_received = 0;
			stats.min_packet_size_sent = 65535;
			stats.min_packet_size_received = 65535;
			stats.ave_packet_size_sent = 0;
			stats.ave_packet_size_received = 0;
			stats.max_packet_size_sent = 0;
			stats.max_packet_size_received = 0;
			stats.time_first_packet.tv_sec = 0;
			stats.time_first_packet.tv_usec = 0;
			stats.time_last_packet.tv_sec = 0;
			stats.time_last_packet.tv_usec = 0;
			stats.drops = 0;
		}
		char * serialize(char *buf, int *left) {
			if(*left < sizeof(struct UDP_Stats_v2)) {
				return NULL;
			}
			memcpy(buf, &stats, sizeof(stats));
			buf += sizeof(stats);
			*left -= sizeof(stats);
			return buf;
		}
};

class ICMP_Flow {
	public:
		struct ICMP_Stats_v2 stats;

		ICMP_Flow(void) {
			stats.type = NETI_ICMP_FLOW;
			stats.remote_ip.s_addr = 0;
			stats.local_ip.s_addr = 0;
			stats.icmp_type = 0;
			stats.icmp_code = 0;
			stats.UNUSED = 0;
			stats.num_badicmpsum = 0;
			stats.num_badipsum = 0;
			stats.num_frag_sent = 0;
			stats.num_frag_received = 0;
			stats.num_dontfrag_sent = 0;
			stats.num_dontfrag_received = 0;
			stats.time_first_packet.tv_sec = 0;
			stats.time_first_packet.tv_usec = 0;
			stats.time_last_packet.tv_sec = 0;
			stats.time_last_packet.tv_usec = 0;
			stats.drops = 0;
		}
		char * serialize(char *buf, int *left) {
			if(*left < sizeof(ICMP_Stats_v2)) {
				return NULL;
			}
			memcpy(buf, &stats, sizeof(stats));
			buf += sizeof(stats);
			*left -= sizeof(stats);
			return buf;
		}
};

class IGMP_Flow {
	public:
		struct IGMP_Stats_v2 stats;
		IGMP_Flow(void) {
			stats.type = NETI_IGMP_FLOW;
			stats.dest_ip.s_addr = 0;
			stats.src_ip.s_addr = 0;
			stats.mcast_ip.s_addr = 0;
			stats.igmp_type = 0;
			stats.igmp_mrt = 0;
			stats.UNUSED = 0;
			stats.flags = 0;
			stats.time_of_packet.tv_sec = 0;
			stats.time_of_packet.tv_usec = 0;
		}
		char * serialize(char *buf, int *left) {
			if(*left < sizeof(IGMP_Stats_v2)) {
				return NULL;
			}
			memcpy(buf, &stats, sizeof(stats));
			buf += sizeof(stats);
			*left -= sizeof(stats);
			return buf;
		}
};

extern map<struct Flow_Key, class UDP_Flow, fkcompare> old_UDP_Flows;
extern map<struct Flow_Key, class TCP_Flow, fkcompare> old_TCP_Flows;
extern map<struct Flow_Key_NoPorts, class ICMP_Flow, fkcompare_noports> old_ICMP_Flows;
extern list<class IGMP_Flow> old_IGMP_Flows;

#endif

