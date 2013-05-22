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

#ifndef NETI_H
#define NETI_H

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>

#include "decode.h"

#ifdef WIN32
#include <winsock2.h>
#define strncasecmp strnicmp
#endif

struct _if_info_t;
struct _if_addr_t;

typedef struct _if_addr_t {
	struct in_addr ip;
	struct in_addr netmask;
	struct _if_addr_t *next;
} if_addr_t;

typedef struct _if_info_t {
	char *name;
	char *description;
	if_addr_t *addrs;
	struct _if_info_t *next;
} if_info_t;

/*  I N C L U D E S  **********************************************************/

/* This macro helps to simplify the differences between Win32 and
   non-Win32 code when printing out the name of the interface */
#ifndef WIN32
    #define PRINT_INTERFACE(i)  i
#else
    #define PRINT_INTERFACE(i)  print_interface(i)
#endif

/*  D E F I N E S  ************************************************************/
#define STD_BUF  1024

#define MAX_PIDFILE_SUFFIX 11 /* uniqueness extension to PID file, see '-R' */

/*
 * you may need to ajust this on the systems which don't have standard
 * paths defined
 */
#ifndef WIN32
    #define DEFAULT_LOG_DIR            "/var/log/neti"
#else
    #define DEFAULT_LOG_DIR            "log"
#endif  /* WIN32 */

#ifdef ACCESSPERMS
    #define FILEACCESSBITS ACCESSPERMS
#else
    #ifdef  S_IAMB
        #define FILEACCESSBITS S_IAMB
    #else
        #define FILEACCESSBITS 0x1FF
    #endif
#endif    

#define DO_IP_CHECKSUMS     0x00000001
#define DO_TCP_CHECKSUMS    0x00000002
#define DO_UDP_CHECKSUMS    0x00000004
#define DO_ICMP_CHECKSUMS   0x00000008
#define DO_IGMP_CHECKSUMS   0x00000010

/* struct to contain the program variables and command line args */
typedef struct _progvars
{
    int checksums_mode;
    int readmode_flag;
#ifdef WIN32
    int syslog_remote_flag;
    char syslog_server[STD_BUF];
    int syslog_server_port;
#endif  /* WIN32 */
    int daemon_flag;
    int pkt_snaplen;
    u_long netmask;
    char pid_filename[STD_BUF];
    const char *log_dir;
    char readfile[STD_BUF];
    char pid_path[STD_BUF];
    const char *interface;
    if_info_t *interface_list;
    char *pcap_cmd;
    char *chroot_dir;
    char pidfile_suffix[MAX_PIDFILE_SUFFIX+1]; /* room for a null */
} PV;

/* struct to collect packet statistics */
typedef struct _PacketCount
{
    u_long total;

    u_long other;
    u_long tcp;
    u_long udp;
    u_long icmp;
    u_long igmp;
    u_long arp;
    u_long eapol;
    u_long ipv6;
    u_long ipx;
    u_long discards;

    u_long frags;           /* number of frags that have come in */

  /* wireless statistics */
    u_long wifi_mgmt;
    u_long wifi_data;
    u_long wifi_control; 
    u_long assoc_req;
    u_long assoc_resp;
    u_long reassoc_req;
    u_long reassoc_resp;
    u_long probe_req;
    u_long probe_resp;
    u_long beacon;
    u_long atim;
    u_long dissassoc;
    u_long auth;
    u_long deauth;
    u_long ps_poll;
    u_long rts;
    u_long cts;
    u_long ack;
    u_long cf_end;
    u_long cf_end_cf_ack;
    u_long data;
    u_long data_cf_ack;
    u_long data_cf_poll;
    u_long data_cf_ack_cf_poll;
    u_long cf_ack;
    u_long cf_poll;
    u_long cf_ack_cf_poll;
} PacketCount;

/*  G L O B A L S  ************************************************************/
extern PV pv;                 /* program vars (command line args) */
extern int datalink;          /* the datalink value */
extern char *progname;        /* name of the program (from argv[0]) */
extern char **progargs;
extern char *username;
extern char *groupname;
extern unsigned long userid;
extern unsigned long groupid;
extern struct passwd *pw;
extern struct group *gr;
extern pcap_t *pd; /* array of packet descriptors per interface */
extern PacketCount pc;        /* packet count information */
extern u_int snaplen;


typedef void (*grinder_t)(Packet *, struct pcap_pkthdr *, u_char *);  /* ptr to the packet processor */

extern grinder_t grinder;

/*  P R O T O T Y P E S  ******************************************************/
int ParseCmdLine(int, char**);
void *InterfaceThread(void *);
int OpenPcap();
int SetPktProcessor();
void CleanExit(int);
void ProcessPacket(char *, struct pcap_pkthdr *, u_char *);
int ShowUsage(char *);
void SigCantHupHandler(int signal);

int neti_main(int, char**);

#endif

