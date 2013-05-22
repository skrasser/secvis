// $Id: capture.h,v 1.7 2005/03/09 14:54:37 sven Exp $
// Code to glue the neti capture sources in
// by Sven Krasser

#ifndef CAPTURE_H
#define CAPTURE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "list.h"

#define PKT_TCP 0
#define PKT_UDP 1

#define SKIPTABLE_DELTA 600	// amount of seconds between skiptable entries
#define MAX_PKT_BUF_LEN 68	// maximum length of payload to buffer for deep packet analysis

struct pkt_info {
	u_int32_t sip, dip;
	char proto;
	u_int16_t sport, dport;
	u_short len;
	struct timeval timestamp;
	char *payload;
	unsigned int payload_len;
};

extern LinkedList pkt_info_list;
extern pthread_mutex_t mutex_pkt_info_list;
extern struct timeval playback_time, ts_lastpkt;
extern double playback_speed;
extern unsigned long buffer_count;
extern listnode **skiptable;

// Defined in neti.cpp
extern bool playback_mode; // true if pcap file is played back

void init_capture();
void log_packet_info(u_int32_t, u_int32_t, char, u_int16_t, u_int16_t, u_short, struct timeval, char*, unsigned int);
void debug_print_pkt_info();
void build_skip_table();

#endif
