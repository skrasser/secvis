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

/*
 *
 * Program: NETI@home
 *
 * Purpose: Check out the README file.
 *
 * Author: Charles Robert Simpson, Jr. (Robby) (neti@ece.gatech.edu)
 *
 * Comments: Much of this code was taken from Martin Roesch's Snort program.
 *           Gotta love open source and code reuse!  See Martin's comments
 *           below:
 * Comments: Ideas and code stolen liberally from Mike Borella's IP Grab
 *           program. Check out his stuff at http://www.borella.net.  I
 *           also have ripped some util functions from TCPdump, plus Mike's
 *           prog is derived from it as well.  All hail TCPdump....
 *
 */

// $Id: neti.cpp,v 1.7 2005/02/18 16:42:36 sven Exp $
// Modified by Sven Krasser

/*  I N C L U D E S  **********************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <sys/stat.h>
#include <syslog.h>
#ifndef WIN32
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif  /* !WIN32 */
#include "timersub.h"

#include "signal.h"
#include "debug.h"
#include "util.h"

#include <ctype.h>

#ifndef WIN32
#include <netdb.h>
#include <string>
#endif

#include "netistats.h"

#include <pthread.h>
#include <iostream>

#include "../capture.h"

extern int errno;

/* exported variables *********************************************************/
PV pv;                  /* program vars */
int datalink;           /* the datalink value */
char *progname;         /* name of the program (from argv[0]) */
char **progargs;
char *username;
char *groupname;
unsigned long userid = 0;
unsigned long groupid = 0;
struct passwd *pw;
struct group *gr;
pcap_t *pd;             /* pcap handle */
time_t lastsendtime;
time_t netistarttime;

PacketCount pc;         /* packet count information */
u_int snaplen;

grinder_t grinder;
static void Restart();

pthread_t thread_neti;
char *pcap_filter = 0;
bool playback_mode = false;

/* Signal handler declarations ************************************************/
static void SigTermHandler(int signal);
static void SigIntHandler(int signal);
static void SigQuitHandler(int signal);
static void SigHupHandler(int signal);
static void SigUsr1Handler(int signal);

/*
 *
 * Function: main(int, char *)
 *
 * Purpose:  The real place that the program handles entry and exit.
 *
 * Arguments: See command line args in README file
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 */
int neti_main(int argc, char* argv[]) 
{
#ifndef WIN32
    #if defined(LINUX) || defined(FREEBSD) || defined(OPENBSD) || defined(SOLARIS)
        sigset_t set;

        sigemptyset(&set);
        sigprocmask(SIG_SETMASK, &set, NULL);
    #else
        sigsetmask(0);
    #endif
#endif  /* !WIN32 */

    /*    malloc_options = "AX";*/

    /* make this prog behave nicely when signals come along */
    signal(SIGTERM, SigTermHandler);
    signal(SIGINT, SigIntHandler);
    signal(SIGQUIT, SigQuitHandler);
    signal(SIGHUP, SigHupHandler);
    signal(SIGUSR1, SigUsr1Handler);

    /*
     * set a global ptr to the program name so other functions can tell what
     * the program name is
     */
    progname = argv[0];
    progargs = argv;

#ifdef WIN32
    if (!init_winsock())
        FatalError("Could not Initialize Winsock!\n");
#endif

    lastsendtime = time(NULL);

    memset(&pv, 0, sizeof(PV));
    
    /* turn on checksum verification by default */
    pv.checksums_mode = 0; //DO_IP_CHECKSUMS | DO_TCP_CHECKSUMS | DO_UDP_CHECKSUMS | DO_ICMP_CHECKSUMS | DO_IGMP_CHECKSUMS;

    /* chew up the command line */
    ParseCmdLine(argc, argv);

    /* If we are running non-root, install a dummy handler instead. */
    if (userid != 0)
        signal(SIGHUP, SigCantHupHandler);
    
    /* set the default logging dir if not set yet */
    /* XXX should probably be done after reading config files */
    if(!pv.log_dir)
    {
        if(!(pv.log_dir = strdup(DEFAULT_LOG_DIR)))
            FatalError("Out of memory setting default log dir\n");
    }
    
    /*
     * if we're not reading packets from a file, open the network interface
     * for reading.. (interfaces are being initalized before the config file
     * is read, so some plugins would be able to start up properly.
     */
    if(!pv.readmode_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Opening interface: %s\n", 
                    PRINT_INTERFACE(pv.interface)););
        /* open up our libpcap packet capture interface */
        OpenPcap();
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Opening file: %s\n", 
                    pv.readfile););

        /* open the packet file for readback */
        OpenPcap();
    }

    /*
     * if daemon mode requested, fork daemon first, otherwise on linux
     * interface will be reset.
     */
    if(pv.daemon_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Entering daemon mode\n"););
        GoDaemon();
    }

    if(pv.daemon_flag 
            || *pv.pidfile_suffix)
    {
        /* ... then create a PID file if not reading from a file */
        if (!pv.readmode_flag && (pv.daemon_flag || *pv.pidfile_suffix))
        {
#ifndef WIN32
            CreatePidFile(pv.interface);
#else
            CreatePidFile("WIN32");
#endif
        }
    }


    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Setting Packet Processor\n"););

    /* set the packet processor (ethernet, slip, t/r, etc ) */
    SetPktProcessor();

#ifndef WIN32
    /* Drop the Chrooted Settings */
    if(pv.chroot_dir)
        SetChroot(pv.chroot_dir, &pv.log_dir);
    
    /* Drop privileges if requested, when initialization is done */
    SetUidGid();
    
#endif /*WIN32*/

    /* Tell 'em who wrote it, and what "it" is */
    DisplayBanner();

    if(pv.daemon_flag)
    {
        LogMessage("NETI@home initialization completed successfully\n");
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Entering pcap loop\n"););

    if(pthread_create(&thread_neti, NULL, &InterfaceThread, NULL)) {
        fprintf(stderr,"Could not spawn packet capture thread.\n");
        exit(0);
    }

    return 0;
}

void ProcessPacket(char *user, struct pcap_pkthdr * pkthdr, u_char * pkt)
{
    Packet p;

    /* reset the packet flags for each packet */
    p.packet_flags = 0;

    pc.total++;

    /* call the packet decoder */
    (*grinder) (&p, pkthdr, pkt);
}


/*
 * Function: ShowUsage(char *)
 *
 * Purpose:  Display the program options and exit
 *
 * Arguments: progname => name of the program (argv[0])
 *
 * Returns: 0 => success
 */
int ShowUsage(char *progname)
{
    fprintf(stdout, "USAGE: %s [-options] <filter options>\n", progname);

#ifdef WIN32
    #define FPUTS_WIN32(msg) fputs(msg,stdout)
    #define FPUTS_UNIX(msg)  NULL
    #define FPUTS_BOTH(msg)  fputs(msg,stdout)
#else
    #define FPUTS_WIN32(msg) 
    #define FPUTS_UNIX(msg)  fputs(msg,stdout)
    #define FPUTS_BOTH(msg)  fputs(msg,stdout)
#endif

    FPUTS_BOTH ("Options:\n");
    FPUTS_UNIX ("        -D         Run NETI@home in background (daemon) mode\n");
    FPUTS_UNIX ("        -g <gname> Run NETI@home gid as <gname> group (or gid) after initialization\n");
    FPUTS_BOTH ("        -i <if>    Listen on interface <if>\n");
    FPUTS_BOTH ("        -l <ld>    Log to directory <ld>\n");
    fprintf(stdout, "        -P <snap>  Set explicit snaplen of packet (default: %d)\n",
                                    SNAPLEN);
    FPUTS_BOTH ("        -r <tf>    Read and process tcpdump file <tf>\n");
    FPUTS_BOTH ("        -f <filter>Set pcap filter\n");
    FPUTS_BOTH ("        -R <id>    Include 'id' in neti_intf<id>.pid file name\n");
    FPUTS_UNIX ("        -t <dir>   Chroots process to <dir> after initialization\n");
    FPUTS_UNIX ("        -u <uname> Run NETI@home uid as <uname> user (or uid) after initialization\n");
    FPUTS_BOTH ("        -V         Show version number\n");
    FPUTS_BOTH ("        -W         Lists available interfaces. (Win32 only)\n");
    FPUTS_BOTH ("        -?         Show this information\n");
    FPUTS_BOTH ("<Filter Options> are standard BPF options, as seen in TCPDump\n");

#undef FPUTS_WIN32
#undef FPUTS_UNIX
#undef FPUTS_BOTH

    return 0;
}



/*
 * Function: ParseCmdLine(int, char *)
 *
 * Purpose:  Parse command line args
 *
 * Arguments: argc => count of arguments passed to the routine
 *            argv => 2-D character array, contains list of command line args
 *
 * Returns: 0 => success, 1 => exit on error
 */
extern char *optarg;                /* for getopt */
extern int   optind;                /* for getopt */

int ParseCmdLine(int argc, char *argv[])
{
    int ch;                         /* storage var for getopt info */
    char errorbuf[PCAP_ERRBUF_SIZE];
    int adaplen;
    const char *valid_options;
    if_info_t *tempdev = NULL;
    int err;
    int devcount;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Parsing command line...\n"););

    /* just to be sane.. */
    username = NULL;
    groupname = NULL;
    pv.pidfile_suffix[0] = 0;

#ifndef WIN32
    /* Unix does not support an argument to -s <wink marty!> OR -E, (-W - no longer) */
    valid_options = "?:Dg:i:l:P:r:R:t:u:VWf:";
#else
    /* Win32 does not support:  -D, -g, -m, -t, -u */
    /* Win32 no longer supports an argument to -s, either! */
    valid_options = "?:i:l:P:r:R:VW";
#endif

    /* loop through each command line var and process it */
    while((ch = getopt(argc, argv, valid_options)) != -1)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Processing cmd line switch: %c\n", ch););
        switch(ch)
        {
            case 'D':                /* daemon mode */
#ifdef WIN32
                FatalError("Setting the Daemon mode is not supported in the "
                           "WIN32 port of NETI@home!  Use 'neti /SERVICE ...' "
                           "instead\n");
#endif
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Daemon mode flag set\n"););
                pv.daemon_flag = 1;
                break;

            case 'g':                /* setgid handler */
#ifdef WIN32
                FatalError("Setting the group id is not supported in the WIN32 port of NETI@home!\n");
#else
                if(groupname != NULL)
                    free(groupname);
                if((groupname = (char *)calloc(strlen(optarg) + 1, 1)) == NULL)
                    FatalPrintError("malloc");

                bcopy(optarg, groupname, strlen(optarg));

                if((groupid = atoi(groupname)) == 0)
                {
                    gr = getgrnam(groupname);
                    if(gr == NULL)
                        FatalError("Group \"%s\" unknown\n", groupname);

                    groupid = gr->gr_gid;
                }
#endif
                break;

            case 'i':
                if(pv.interface)
                {
                    FatalError("Cannot specify more than one network "
                               "interface on the command line.\n");
                }
                /* first, try to handle the "-i1" case, where an interface
                 * is specified by number.  If this fails, then fall-through
                 * to the case outside the ifdef/endif, where an interface
                 * can be specified by its fully qualified name, like as is
                 * shown by running 'neti -W', ie.
                 * "\Device\Packet_{12345678-90AB-CDEF-1234567890AB}"
                 */
                adaplen = atoi(optarg);
                if( adaplen > 0 )
                {
                    pv.interface_list = get_interface_list(&err, errorbuf);
                    if(pv.interface_list == NULL) {
                        perror(errorbuf);
                        exit(1);
                    }
                    tempdev = pv.interface_list;
                    devcount = 1;
                    while(tempdev != NULL && devcount != adaplen) {
                        tempdev = tempdev->next;
                        devcount++;
                    }
                    if(tempdev != NULL && devcount == adaplen) {
                        pv.interface = tempdev->name;
                    }
                    else {
                        pv.interface = NULL;
                    }

                    if ( pv.interface == NULL )
                    {
                        LogMessage("Invalid interface '%d'.", atoi(optarg));
                        exit(1);
                    }


                    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Interface = %s\n",
                                PRINT_INTERFACE(pv.interface)));
                }
                else
                /* this code handles the case in which the user specifies
                   the entire name of the interface and it is compiled
                   regardless of which OS you have */
                {
		    pv.interface = optarg;
		    DEBUG_WRAP(DebugMessage(DEBUG_INIT,
                        "Interface = %s\n",
                        PRINT_INTERFACE(pv.interface)););
                }
                // XXX - Need error checking to make sure is a valid name
                break;

            case 'l':                /* use log dir <X> */
                if(!(pv.log_dir = strdup(optarg)))
                {
                    FatalError("Out of memory processing command line\n");
                }

                if(access(pv.log_dir, 2) != 0)
                {
                    FatalError("log directory '%s' does not exist\n", 
                            pv.log_dir);
                }
                break;

            case 'P':  /* explicitly define snaplength of packets */
                pv.pkt_snaplen = atoi(optarg);
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Snaplength of Packets set to: %d\n", pv.pkt_snaplen););
                break;

            case 'r':  /* read packets from a TCPdump file instead
                        * of the net */
                strlcpy(pv.readfile, optarg, STD_BUF);
                pv.readmode_flag = 1;
		
		playback_mode = true;
		
                break;

            case 'R': /* augment pid file name CPW*/
                if (strlen(optarg) < MAX_PIDFILE_SUFFIX && strlen(optarg) > 0)
                {
                    if (!strstr(optarg, "..") && !(strstr(optarg, "/")))
                    {
                        snprintf(pv.pidfile_suffix, MAX_PIDFILE_SUFFIX, "%s",
                                optarg);
                    }
                    else
                    {
                        FatalError("ERROR: illegal pidfile suffix: %s\n",
                                optarg);
                    }
                }
                else
                {
                    FatalError("ERROR: pidfile suffix length problem: %d\n",
                            strlen(optarg) );
                }
                break;

            case 't':  /* chroot to the user specified directory */
#ifdef WIN32
                FatalError("Setting the chroot directory is not supported in "
                           "the WIN32 port of NETI@home!\n");
#endif  /* WIN32 */
                if(!(pv.chroot_dir = strdup(optarg)))
                    FatalError("Out of memory processing command line\n");
                break;

            case 'u':  /* setuid */
#ifdef WIN32
                FatalError("Setting the user id is not "
                           "supported in the WIN32 port of NETI@home!\n");
#else
                if((username = (char *)calloc(strlen(optarg) + 1, 1)) == NULL)
                    FatalPrintError("malloc");

                bcopy(optarg, username, strlen(optarg));

                if((userid = atoi(username)) == 0)
                {
                    pw = getpwnam(username);
                    if(pw == NULL)
                        FatalError("User \"%s\" unknown\n", username);

                    userid = pw->pw_uid;
                }
                else
                {
                    pw = getpwuid(userid);
                    if(pw == NULL)
                        FatalError(
                                "Can not obtain username for uid: %lu\n",
                                (u_long) userid);
                }

                if(groupname == NULL)
                {
                    char name[256];

                    snprintf(name, 255, "%lu", (u_long) pw->pw_gid);

                    if((groupname = (char *)calloc(strlen(name) + 1, 1)) == NULL)
                    {
                        FatalPrintError("malloc");
                    }
                    groupid = pw->pw_gid;
                }
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "UserID: %lu GroupID: %lu\n",
                    (unsigned long) userid, (unsigned long) groupid););
#endif  /* !WIN32 */
                break;

            case 'V': /* prog ver already gets printed out, so we
                       * just exit */
                DisplayBanner();
                exit(0);

            case 'W':
                pv.interface_list = get_interface_list(&err, errorbuf);
                if(pv.interface_list == NULL) {
                    switch(err) {
                        case CANT_GET_INTERFACE_LIST:
                            printf("CANT_GET_INTERFACE_LIST: %s\n", errorbuf);
                            exit(0);
                            break;
                        case NO_INTERFACES_FOUND:
                            printf("NO_INTERFACES_FOUND: %s\n", errorbuf);
                            exit(0);
                            break;
                        default:
                            printf("Unknown Error: %d\t%s\n", err, errorbuf);
                            exit(0);
                            break;
                    }
                }
                tempdev = pv.interface_list;
                devcount = 1;
                DisplayBanner();
                printf("Interface\tDevice\tDescription\n");
                printf("------------------------------\n");
                while(tempdev != NULL) {
                    printf("%d\t", devcount);
                    if(tempdev->name) {
                        printf("%s\t", tempdev->name);
                    }
                    else {
                        printf("???\t");
                    }
                    if(tempdev->description) {
                        printf("%s\n", tempdev->description);
                    }
                    else {
                        printf("\n");
                    }
                    tempdev = tempdev->next;
                    devcount++;
                }
                printf("\n");

                exit(0);
                break;

            case '?':  /* show help and exit */
                DisplayBanner();
                ShowUsage(progname);
                exit(0);
		break;
		
            case 'f':  // pcap filter
                if((pcap_filter = (char *)calloc(strlen(optarg) + 1, 1)) == NULL)
                    FatalPrintError("malloc");

                bcopy(optarg, pcap_filter, strlen(optarg));
		std::cout << "pcap filter is " << pcap_filter << std::endl;
                break;
        }
    }

    /* TODO relocate all of this to later in startup process */

    pv.pcap_cmd = pcap_filter;

    if((pv.interface == NULL) && !pv.readmode_flag)
    {
        pv.interface = pcap_lookupdev(errorbuf);

        if(pv.interface == NULL)
            FatalError( "Failed to lookup for interface: %s."
                    " Please specify one with -i switch\n", errorbuf);
    }

    return 0;
}



/*
 * Function: SetPktProcessor()
 *
 * Purpose:  Set which packet processing function we're going to use based on
 *           what type of datalink layer we're using
 *
 * Arguments: int num => number of interface
 *
 * Returns: 0 => success
 */
int SetPktProcessor()
{
    switch(datalink)
    {
        case DLT_EN10MB:        /* Ethernet */
            grinder = DecodeEthPkt;
            break;

#ifdef DLT_IEEE802_11
        case DLT_IEEE802_11:
            grinder = DecodeIEEE80211Pkt;
            break;
#endif
        case 13:
        case DLT_IEEE802:                /* Token Ring */
            grinder = DecodeTRPkt;
            break;

        case DLT_FDDI:                /* FDDI */
            grinder = DecodeFDDIPkt;
            break;

#ifdef DLT_CHDLC
        case DLT_CHDLC:              /* Cisco HDLC */
            grinder = DecodeChdlcPkt;
            break;
#endif

        case DLT_SLIP:                /* Serial Line Internet Protocol */
            grinder = DecodeSlipPkt;
            break;

        case DLT_PPP:                /* point-to-point protocol */
            grinder = DecodePppPkt;
            break;

#ifdef DLT_PPP_SERIAL
        case DLT_PPP_SERIAL:         /* PPP with full HDLC header*/
            grinder = DecodePppSerialPkt;
            break;
#endif

#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            grinder = DecodeLinuxSLLPkt;
            break;
#endif

#ifdef DLT_PFLOG
        case DLT_PFLOG:
            grinder = DecodePflog;
            break;
#endif

#ifdef DLT_LOOP
        case DLT_LOOP:
#endif
        case DLT_NULL:            /* loopback and stuff.. you wouldn't perform
                                   * intrusion detection on it, but it's ok for
                                   * testing. */
            grinder = DecodeNullPkt;
            break;

#ifdef DLT_RAW /* Not supported in some arch or older pcap
                * versions */
        case DLT_RAW:
            grinder = DecodeRawPkt;
            break;
#endif
            /*
             * you need the I4L modified version of libpcap to get this stuff
             * working
             */
#ifdef DLT_I4L_RAWIP
        case DLT_I4L_RAWIP:
            grinder = DecodeI4LRawIPPkt;
            break;
#endif

#ifdef DLT_I4L_IP
        case DLT_I4L_IP:
            grinder = DecodeEthPkt;
            break;
#endif

#ifdef DLT_I4L_CISCOHDLC
        case DLT_I4L_CISCOHDLC:
            grinder = DecodeI4LCiscoIPPkt;
            break;
#endif

        default:                        /* oops, don't know how to handle this one */
            ErrorMessage("\n%s cannot handle data link type %d\n",
                    progname, datalink);
            CleanExit(1);
    }

    return 0;
}


/*
 * Function: void *InterfaceThread(void *arg)
 *
 * Purpose: wrapper for pthread_create() to create a thread per interface
 */
void *InterfaceThread(void *arg)
{
    static int intnum = 0;
    int myint;
    struct timeval starttime;
    struct timeval endtime;
    struct timeval difftime;
    struct timezone tz;

    myint = intnum;
    intnum++;

    bzero((char *) &tz, sizeof(tz));
    gettimeofday(&starttime, &tz);

    netistarttime = time(NULL);

    /* Read all packets on the device.  Continue until cnt packets read */
    if(pcap_loop(pd, -1, (pcap_handler) ProcessPacket, NULL) < 0)
    {
        if(pv.daemon_flag)
            syslog(LOG_CONS | LOG_DAEMON, "pcap_loop: %s", pcap_geterr(pd));
        else
            ErrorMessage("pcap_loop: %s\n", pcap_geterr(pd));

        CleanExit(1);
    }

    gettimeofday(&endtime, &tz);

    TIMERSUB(&endtime, &starttime, &difftime);

    printf("Run time for packet processing was %lu.%u seconds\n", 
            difftime.tv_sec, difftime.tv_usec);

    CleanExit(0);

    return NULL;                /* avoid warnings */
}



/****************************************************************************
 *
 * Function: OpenPcap(char *, int)
 *
 * Purpose:  Open the libpcap interface
 *
 * Arguments: intf => name of the interface to open
 *            num  => number of the interface (to fill-in datalink and pd)
 *
 * Returns: 0 => success, exits on problems
 *
 ****************************************************************************/
int OpenPcap()
{
    bpf_u_int32 localnet, netmask;        /* net addr holders */
    struct bpf_program fcode;        /* Finite state machine holder */
    char errorbuf[PCAP_ERRBUF_SIZE];        /* buffer to put error strings in */
    int err;
    bpf_u_int32 defaultnet = 0xFFFFFF00;
    if_info_t *tempdev;

    /* if we're not reading packets from a file */
    if(pv.interface == NULL)
    {
        if (!pv.readmode_flag)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_INIT,
                    "pv.interface is NULL, looking up interface....   "););
            /* look up the device and get the handle */
            pv.interface = pcap_lookupdev(errorbuf);
    
            DEBUG_WRAP(DebugMessage(DEBUG_INIT,
                    "found interface %s\n", PRINT_INTERFACE(pv.interface)););
            /* uh oh, we couldn't find the interface name */
            if(pv.interface == NULL)
            {
                FatalError("OpenPcap() interface lookup: \n\t%s\n",
               errorbuf);
            }
        }
        else
        {
            /* interface is null and we are in readmode */
            /* some routines would hate it to be NULL */
            pv.interface = "[reading from a file]"; 
        }
    }

    if (!pv.readmode_flag) {
        pv.interface_list = get_interface_list(&err, errorbuf);
        if(pv.interface_list == NULL) {
            switch(err) {
                case CANT_GET_INTERFACE_LIST:
                    FatalError("OpenPcap() CANT_GET_INTERFACE_LIST: %s\n", errorbuf);
                    break;
                case NO_INTERFACES_FOUND:
                    FatalError("OpenPcap() NO_INTERFACES_FOUND: %s\n", errorbuf);
                    break;
                default:
                    FatalError("OpenPcap() Unknown Error: %d\t%s\n", err, errorbuf);
            }
        }
        if(strcasecmp(pv.interface, "any") != 0) {
            for(tempdev = pv.interface_list; tempdev != NULL; tempdev = tempdev->next) {
                if(strcasecmp(tempdev->name, pv.interface) == 0) {
                    break;
                }
            }
            if(tempdev == NULL) {
                // End of list found without finding device!!!
                FatalError("OpenPcap() interface_list lookup\n");
            }
        }
        LogMessage("\nInitializing Network Interface %s\n", 
                PRINT_INTERFACE(pv.interface));
    }
    else 
        LogMessage("TCPDUMP file reading mode.\n");

    if (!pv.readmode_flag)
    {
        if(pv.pkt_snaplen)        /* if it's set let's try it... */
        {
            if(pv.pkt_snaplen < MIN_SNAPLEN)        /* if it's < MIN set it to
                                                     * MIN */
            {
                /* XXX: Warning message, specidifed snaplen too small,
                 * snaplen set to X
                 */
                 snaplen = MIN_SNAPLEN;
            }
            else
            {
                 snaplen = pv.pkt_snaplen;
            }
         }
         else
         {
             snaplen = SNAPLEN;        /* otherwise let's put the compiled value in */
         }
        
        DEBUG_WRAP(DebugMessage(DEBUG_INIT,
                "snaplength info: set=%d/compiled=%d/wanted=%d\n",
                snaplen,  SNAPLEN, pv.pkt_snaplen););
    
        /* get the device file descriptor */
        pd = pcap_open_live(pv.interface, snaplen,
                0, READ_TIMEOUT, errorbuf);

    }
    else
    {   /* reading packets from a file */

        /* open the file */
        pd = pcap_open_offline(pv.readfile, errorbuf);

        /* the file didn't open correctly */
        if(pd == NULL)
        {
            FatalError("unable to open file \"%s\" for readback: %s\n",
                       pv.readfile, errorbuf);
        }
        /*
         * set the snaplen for the file (so we don't get a lot of extra crap
         * in the end of packets
         */
        snaplen = pcap_snapshot(pd);
    }

    /* something is wrong with the opened packet socket */
    if(pd == NULL)
    {
        if(strstr(errorbuf, "Permission denied"))
        {
            FatalError("You don't have permission to"
                       " sniff.\nTry doing this as root.\n");
        }
        else
        {
            FatalError("OpenPcap() device %s open: \n\t%s\n",
                       PRINT_INTERFACE(pv.interface), errorbuf);
        }
    }
    /* get local net and netmask */
    if(pcap_lookupnet(pv.interface, &localnet, &netmask, errorbuf) < 0)
    {
       if (!pv.readmode_flag)
       {
           ErrorMessage("OpenPcap() device %s network lookup: \n"
                        "\t%s\n",
                        PRINT_INTERFACE(pv.interface), errorbuf);

       }
        /*
         * set the default netmask to 255.255.255.0 (for stealthed
         * interfaces)
         */
        netmask = htonl(defaultnet);
    }

    pv.netmask = netmask;

    /* compile BPF filter spec info fcode FSM */
    if(pcap_compile(pd, &fcode, pv.pcap_cmd, 1, netmask) < 0)
    {
        FatalError("OpenPcap() FSM compilation failed: \n\t%s\n"
                   "PCAP command: %s\n", pcap_geterr(pd), pv.pcap_cmd);
    }
    /* set the pcap filter */
    if(pcap_setfilter(pd, &fcode) < 0)
    {
        FatalError("OpenPcap() setfilter: \n\t%s\n",
                   pcap_geterr(pd));
    }
    
    /* get data link type */
    datalink = pcap_datalink(pd);

    if(datalink < 0)
    {
        FatalError("OpenPcap() datalink grab: \n\t%s\n",
                   pcap_geterr(pd));
    }
    return 0;
}

/* Signal Handlers ************************************************************/

static void SigTermHandler(int signal)
{
    CleanExit(0);
}

static void SigIntHandler(int signal)
{
    CleanExit(0);
}   

static void SigQuitHandler(int signal)
{
    CleanExit(0);
}

static void SigHupHandler(int signal)
{
    Restart();
}

static void SigUsr1Handler(int signal)
{
#ifndef WIN32
#if defined(LINUX) || defined(FREEBSD) || defined(OPENBSD) || defined(SOLARIS)
    sigset_t set;

    /* XXX why do we unblock all signals here? */
    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);
#else
    sigsetmask(0);
#endif
#endif  /* !WIN32 */
}

/**
 * dummy signal handler for nonroot users or chroot.
 *
 * @param signal signal to exec
 */
void SigCantHupHandler(int signal)
{
        LogMessage("Reload via Signal HUP does not work if you aren't root or are chroot'ed\n");
}

/****************************************************************************
 *
 * Function: CleanExit()
 *
 * Purpose:  Clean up misc file handles and such and exit
 *
 * Arguments: exit value;
 *
 * Returns: void function
 *
 ****************************************************************************/
void CleanExit(int exit_val)
{
    /* This function can be called more than once.  For example,
     * once from the SIGINT signal handler, and once recursively
     * as a result of calling pcap_close() below.  We only need
     * to perform the cleanup once, however.  So the static
     * variable already_exiting will act as a flag to prevent
     * double-freeing any memory.  Not guaranteed to be
     * thread-safe, but it will prevent the simple cases.
     */
    static int already_exiting = 0;
    if( already_exiting != 0 )
    {
        return;
    }
    already_exiting = 1;

    /* free allocated memory */

    /* close pcap */
    if(pd)
        pcap_close(pd);

#ifdef WIN32
	WSACleanup();
#endif

    if(pv.interface_list) {
        free_interface_list(pv.interface_list);
        pv.interface_list = NULL;
    }

    LogMessage("NETI@home exiting\n");

    /* remove pid file */
    if(pv.pid_filename)
        unlink(pv.pid_filename);

    /* exit */
  //  exit(exit_val);
  
  // (sven)
  // don't exit -- gfx thread is still displaying data...
  std::cout << "Capturing finished" << std::endl;
  
  if(playback_mode) {
    std::cout << "Building skip table" << std::endl;
    build_skip_table();
    std::cout << "Skip table initialized" << std::endl;
  }
  
  while(1) { usleep(1000000); }
  // has to be changed to join other threads at some point...
}

static void Restart()
{
    /* free allocated memory */

    /* close pcap */
    if(pd)
        pcap_close(pd);

    /* remove pid file */

    if(pv.pid_filename)
        unlink(pv.pid_filename);
    LogMessage("Restarting NETI@home\n");

    /* re-exec NETI@home */
#ifdef PARANOID
    execv(progname, progargs);
#else
    execvp(progname, progargs);
#endif

    /* only get here if we failed to restart */
    LogMessage("Restarting %s failed: %s", progname, strerror(errno));
    exit(1);
}

/* vim: smartindent:expandtab:sw=4:ts=4:tw=0
 */
