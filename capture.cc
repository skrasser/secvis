// $Id: capture.cc,v 1.10 2005/03/09 14:54:37 sven Exp $
// Code to glue the neti capture sources in
// by Sven Krasser

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iostream>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <math.h>

#include "capture.h"
#include "capture/decode.h"
#include "list.h"

// Globals
LinkedList pkt_info_list;	// liked list that holds all packet information
pthread_mutex_t mutex_pkt_info_list = PTHREAD_MUTEX_INITIALIZER;
struct timeval playback_time;		// the time in playback mode (real time uses system time)
struct timeval ts_lastpkt;
double playback_speed;		// the speed of the playback, 1.0 for real-time playback
unsigned long buffer_count = 0;
listnode **skiptable = 0;

static struct itimerval timer_value;	// timer for virtual wall time in playback mode
static int playback_progress;		// time in msec the playback time is updated
static struct timeval ts_firstpkt;	// timestamp of first packet
static bool have_firstpkt = false;	// indicates whether the first packet has been processed in playback mode

static void sig_alarm_handler(int signal) {
	playback_time.tv_usec += (long)(playback_speed * playback_progress * 1000);
	if(playback_speed > 0.0 || playback_time.tv_usec >= 0.0) {
		playback_time.tv_sec += playback_time.tv_usec / 1000000;
		playback_time.tv_usec %= 1000000;
	} else {
		long carry;
		// we're replaying backwards and have a negative time value
		carry = playback_time.tv_usec / 1000000 - 1;
		playback_time.tv_usec -= carry * 1000000;
		playback_time.tv_sec += carry;
	}
}

void set_playback_progress(int intv) {	
	playback_progress = intv;
	timer_value.it_interval.tv_usec = 1000 * intv;
}

void init_capture() {
	if(playback_mode) {
		std::cout << "Setting up timer" << std::endl;
		signal(SIGALRM, sig_alarm_handler);
		
		playback_speed = 1.0;
		
		struct sigaction sact;
		sigemptyset(&sact.sa_mask);
		sact.sa_flags = 0;
		sact.sa_handler = sig_alarm_handler;
		sigaction(SIGALRM, &sact, NULL);
		
		playback_time.tv_sec = playback_time.tv_usec = 0;
		
		timer_value.it_interval.tv_sec = 0;
		timer_value.it_value.tv_sec = 0;
		timer_value.it_value.tv_usec = 1; // don't use zero here--timer won't start
		set_playback_progress(50);
		
		if(setitimer(ITIMER_REAL, &timer_value, NULL)) {
			std::cout << "Could not set up timer for packet playback" << std::endl;
			exit(1);
		}
	}
}

void log_packet_info(u_int32_t ip_src, u_int32_t ip_dst, char proto, u_int16_t sport, u_int16_t dport, 
	u_short len, struct timeval timestamp, char *payload, unsigned int payload_len) {
	struct pkt_info *pinfo;
	if ((pinfo = (struct pkt_info*)malloc(sizeof(struct pkt_info))) == 0) {
		std::cout << "Could not store packet information" << std::endl;
	}
	pinfo->sip = ntohl(ip_src);
	pinfo->dip = ntohl(ip_dst);
	pinfo->sport = sport;
	pinfo->dport = dport;
	pinfo->len = len;
	pinfo->proto = proto;
	pinfo->timestamp = timestamp;
	pinfo->payload = payload;
	pinfo->payload_len = payload_len;
	if(!have_firstpkt && playback_mode) {
		have_firstpkt = true;
		ts_firstpkt = timestamp;
		
		ts_lastpkt.tv_sec = 0;
		ts_lastpkt.tv_usec = 0;
	}
	if(playback_mode) {
		// in playback mode: normalize packet timestamps to be offsets to the first packet
		pinfo->timestamp.tv_sec -= ts_firstpkt.tv_sec;
		pinfo->timestamp.tv_usec -= ts_firstpkt.tv_usec;
		
		// remember timestamp of last packet
		// packets may be reorder in file, so check if this is really the last packet
		if(pinfo->timestamp.tv_sec > ts_lastpkt.tv_sec) // well, usecs are not considered here...
			ts_lastpkt = pinfo->timestamp;
	}
	pthread_mutex_lock(&mutex_pkt_info_list);
	pkt_info_list.append(pinfo);
	buffer_count++;
	pthread_mutex_unlock(&mutex_pkt_info_list);
}

void build_skip_table() {
	listnode *current;
	struct pkt_info *pinfo;
	unsigned int i;
	listnode **tempskiptable;
	
	i = ts_lastpkt.tv_sec / SKIPTABLE_DELTA; // one entry for SKIPTABLE_DELTA seconds worth of capture data
	
	tempskiptable = new listnode*[i + 1];
	
	i = 0;
	
	current = pkt_info_list.get_first();
	while(current) {
		pinfo = (struct pkt_info*)(current->data);
		if(pinfo->timestamp.tv_sec >= i * SKIPTABLE_DELTA) {
			tempskiptable[i] = current;
			i++;
		}
		current = current->next;
	}
	skiptable = tempskiptable;
}

void debug_print_pkt_info() {
	listnode *current;
	struct pkt_info *pinfo;
	in_addr s, d;
	pthread_mutex_lock(&mutex_pkt_info_list);
	current = pkt_info_list.get_first();
	while(current) {
		pinfo = (struct pkt_info*)(current->data);
		s.s_addr = pinfo->sip;
		d.s_addr = pinfo->dip;
		
		printf("%s ", inet_ntoa(s));
		printf("%s %d %d %d %d\n", inet_ntoa(d), pinfo->proto, pinfo->sport, pinfo->dport, pinfo->len);
		current = current->next;
	}
	pthread_mutex_unlock(&mutex_pkt_info_list);
}
