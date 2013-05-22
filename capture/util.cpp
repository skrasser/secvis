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

#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* !WIN32 */
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#ifndef WIN32
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <limits.h>
#endif /* !WIN32 */
#include <fcntl.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "neti.h"
#include <ctype.h>
#include "debug.h"
#include "util.h"

#ifdef WIN32
#include "win32/WIN32-Code/name.h"
#endif

#ifdef PATH_MAX
#define PATH_MAX_UTIL PATH_MAX
#else
#define PATH_MAX_UTIL 1024
#endif /* PATH_MAX */

#define MIN_PACKET_SIZE 68 /* minimum amount of packet data we can read */
#define MAX_WIN_IF_NAME_LEN 511

#ifndef _PATH_VARRUN
char _PATH_VARRUN[STD_BUF];
#endif



/****************************************************************************
 *
 * Function: DisplayBanner()
 *
 * Purpose:  Show valuable proggie info
 *
 * Arguments: None.
 *
 * Returns: 0 all the time
 *
 ****************************************************************************/
int DisplayBanner()
{
 /*   printf("\n-*> NETI@home <*-\nVersion 2.0\n"
            "By Charles Robert Simpson, Jr. (neti@ece.gatech.edu, www.neti.gatech.edu)\n"
            "Portions of Code Lovingly Ripped from Snort and Ethereal\n\n"); */
    return 0;
}



/****************************************************************************
 *
 * Function: strip(char *)
 *
 * Purpose: Strips a data buffer of CR/LF/TABs.  Replaces CR/LF's with
 *          NULL and TABs with spaces.
 *
 * Arguments: data => ptr to the data buf to be stripped
 *
 * Returns: size of the newly stripped string
 *
 ****************************************************************************/
int strip(char *data)
{
    int size;
    char *end;
    char *idx;

    idx = data;
    end = data + strlen(data);
    size = end - idx;

    while(idx != end)
    {
        if((*idx == '\n') ||
                (*idx == '\r'))
        {
            *idx = 0;
            size--;
        }
        if(*idx == '\t')
        {
            *idx = ' ';
        }
        idx++;
    }

    return size;
}


/*
 * error message printing routines. in daemon mode these would go into
 * syslog.
 *
 * first would allow to print formatted error messages (similar to printf) and
 * the second is similar to perror.
 *
 */

void PrintError(const char *str)
{
    if(pv.daemon_flag)
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "%s:%m", str);
    else
        perror(str);
}


/*
 * Function: ErrorMessage(const char *, ...)
 *
 * Purpose: Print a message to stderr.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void ErrorMessage(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);

    if(pv.daemon_flag)
    {
        vsnprintf(buf, STD_BUF, format, ap);
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }
    va_end(ap);
}

/*
 * Function: LogMessage(const char *, ...)
 *
 * Purpose: Print a message to stdout or with logfacility.
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void LogMessage(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    if(!pv.daemon_flag)
        return;

    va_start(ap, format);

    if(pv.daemon_flag)
    {
        vsnprintf(buf, STD_BUF, format, ap);
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
    }
    else
    {
        vfprintf(stderr, format, ap);
    }
    va_end(ap);
}


/*
 * Function: FatalError(const char *, ...)
 *
 * Purpose: When a fatal error occurs, this function prints the error message
 *          and cleanly shuts down the program
 *
 * Arguments: format => the formatted error string to print out
 *            ... => format commands/fillers
 *
 * Returns: void function
 */
void FatalError(const char *format,...)
{
    char buf[STD_BUF+1];
    va_list ap;

    va_start(ap, format);

    vsnprintf(buf, STD_BUF, format, ap);

    if(pv.daemon_flag)
    {
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "FATAL ERROR: %s", buf);
    }
    else
    {
        fprintf(stderr, "ERROR: %s", buf);
        fprintf(stderr,"Fatal Error, Quitting..\n");
    }

    exit(1);
}

void FatalPrintError(const char *msg)
{
    PrintError(msg);
    exit(1);
}

/****************************************************************************
 *
 * Function: CreatePidFile(const char *)
 *
 * Purpose:  Creates a PID file
 *
 * Arguments: Interface opened.
 *
 * Returns: void function
 *
 ****************************************************************************/
void CreatePidFile(const char *intf)
{
    FILE *pid_file;
    struct stat pt;
#ifdef WIN32
    char dir[STD_BUF + 1];
#endif

    if (!pv.readmode_flag) 
    {
#ifndef _PATH_VARRUN
#ifndef WIN32
        strlcpy(_PATH_VARRUN, "/var/run/", 10);
#else
        if (GetCurrentDirectory(sizeof (dir)-1, dir))
            strncpy (_PATH_VARRUN, dir, sizeof(dir)-1);
#endif  /* WIN32 */
#endif  /* _PATH_VARRUN */

        stat(_PATH_VARRUN, &pt);

        if(!S_ISDIR(pt.st_mode) || access(_PATH_VARRUN, W_OK) == -1)
        {
            LogMessage("WARNING: _PATH_VARRUN is invalid, trying "
                    "/var/log...\n");
            strncpy(pv.pid_path, "/var/log/", strlen("/var/log/"));
            stat(pv.pid_path, &pt);

            if(!S_ISDIR(pt.st_mode) || access(pv.pid_path, W_OK) == -1)
            {
                LogMessage("WARNING: %s is invalid, logging NETI "
                        "PID path to log directory (%s)\n", pv.pid_path,
                        pv.log_dir);
                snprintf(pv.pid_path, STD_BUF, "%s/", pv.log_dir);
            }
        }
        else
        {
            LogMessage("PID path stat checked out ok, PID path set to %s\n", _PATH_VARRUN);
            strlcpy(pv.pid_path, _PATH_VARRUN, STD_BUF);
        }
    }

    if(intf == NULL || pv.pid_path == NULL)
    {
        /* pv.pid_path should have some value by now
         *          * so let us just be sane.
         *                   */
        FatalError("CreatePidFile() failed to lookup interface or pid_path is unknown!\n");
    }

    snprintf(pv.pid_filename, STD_BUF,  "%s/neti_%s%s.pid", pv.pid_path, intf,
            pv.pidfile_suffix);

    pid_file = fopen(pv.pid_filename, "w");

    if(pid_file)
    {
        int pid = (int) getpid();

        LogMessage("Writing PID \"%d\" to file \"%s\"\n", pid, pv.pid_filename);
        fprintf(pid_file, "%d\n", pid);
        fclose(pid_file);
    }
    else
    {
        ErrorMessage("Failed to create pid file %s", pv.pid_filename);
        pv.pid_filename[0] = 0;
    }
}


/****************************************************************************
 *
 * Function: SetUidGid(char *)
 *
 * Purpose:  Sets safe UserID and GroupID if needed
 *
 * Arguments: none
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetUidGid(void)
{
#ifndef WIN32
    if(groupname != NULL)
    {
        if(setgid(groupid) < 0)
            FatalError("Can not set gid: %lu\n", (u_long) groupid);

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Set gid to %lu\n", groupid););
    }
    if(username != NULL)
    {
        if(getuid() == 0 && initgroups(username, groupid) < 0)
            FatalError("Can not initgroups(%s,%lu)",
                    username, (u_long) groupid);

        /** just to be on a safe side... **/
        endgrent();
        endpwent();

        if(setuid(userid) < 0)
            FatalError("Can not set uid: %lu\n", (u_long) userid);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Set gid to %lu\n", groupid););
    }
#endif  /* WIN32 */
}

/****************************************************************************
 *
 * Function: GoDaemon()
 *
 * Purpose: Puts the program into daemon mode, nice and quiet like....
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void GoDaemon(void)
{
#ifndef WIN32
    pid_t fs;

    LogMessage("Initializing daemon mode\n");

    if(getppid() != 1)
    {
        fs = fork();

        if(fs > 0)
            exit(0);                /* parent */

        if(fs < 0)
        {
            perror("fork");
            exit(1);
        }
        setsid();
    }
    /* redirect stdin/stdout/stderr to /dev/null */
    close(0);
    close(1);
    close(2);

#ifdef DEBUG
    open("/tmp/neti.debug", O_CREAT | O_RDWR);
#else
    open("/dev/null", O_RDWR);
#endif

    dup(0);
    dup(0);
#endif /* ! WIN32 */
    return;
}

/** 
 * Chroot and adjust the pv.log_dir reference 
 * 
 * @param directory directory to chroot to
 * @param logdir ptr to pv.log_dir
 */
void SetChroot(const char *directory, const char **logstore)
{
#ifdef WIN32
    FatalError("SetChroot() should not be called under Win32!\n");
#else
    char *absdir;
    int abslen;
    const char *logdir;
    
    if(!directory || !logstore)
    {
        FatalError("Null parameter passed\n");
    }

    logdir = *logstore;

    if(logdir == NULL || *logdir == '\0')
    {
        FatalError("Null log directory\n");
    }    

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"SetChroot: %s\n",
                                       CurrentWorkingDir()););
    
    logdir = GetAbsolutePath(logdir);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "SetChroot: %s\n",
                                       CurrentWorkingDir()));
    
    logdir = strdup(logdir);

    if(logdir == NULL)
    {
        FatalError("SetChroot: Out of memory");
    }
    
    /* change to the directory */
    if(chdir(directory) != 0)
    {
        FatalError("SetChroot: Can not chdir to \"%s\": %s\n", directory, 
                   strerror(errno));
    }

    /* always returns an absolute pathname */
    absdir = CurrentWorkingDir();

    if(absdir == NULL)                          
    {
        FatalError("NULL Chroot found\n");
    }
    
    abslen = strlen(absdir);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "ABS: %s %d\n", absdir, abslen););
    
    /* make the chroot call */
    if(chroot(absdir) < 0)
    {
        FatalError("Can not chroot to \"%s\": absolute: %s: %s\n",
                   directory, absdir, strerror(errno));
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"chroot success (%s ->", absdir););
    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"%s)\n ", CurrentWorkingDir()););
    
    /* change to "/" in the new directory */
    if(chdir("/") < 0)
    {
        FatalError("Can not chdir to \"/\" after chroot: %s\n", 
                   strerror(errno));
    }    

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"chdir success (%s)\n",
                            CurrentWorkingDir()););


    if(strncmp(absdir, logdir, strlen(absdir)))
    {
        FatalError("Absdir is not a subset of the logdir");
    }
    
    if(abslen >= strlen(logdir))
    {
        *logstore = "/";
    }
    else
    {
        *logstore = logdir + abslen;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_INIT,"new logdir from %s to %s\n",
                            logdir, *logstore));

    /* install the I can't do this signal handler */
    signal(SIGHUP, SigCantHupHandler);
#endif /* !WIN32 */
}


/**
 * Return a ptr to the absolute pathname of NETI@home.  This memory must
 * be copied to another region if you wish to save it for later use.
 */
char *CurrentWorkingDir(void)
{
    static char buf[PATH_MAX_UTIL + 1];
    
    if(getcwd((char *) buf, PATH_MAX_UTIL) == NULL)
    {
        return NULL;
    }

    buf[PATH_MAX_UTIL] = '\0';

    return (char *) buf;
}

/**
 * Given a directory name, return a ptr to a static 
 */
char *GetAbsolutePath(const char *dir)
{
    char *savedir, *dirp;
    static char buf[PATH_MAX_UTIL + 1];

    if(dir == NULL)
    {
        return NULL;
    }

    savedir = strdup(CurrentWorkingDir());

    if(savedir == NULL)
    {
        return NULL;
    }

    if(chdir(dir) < 0)
    {
        LogMessage("Can't change to directory: %s\n", dir);
        free(savedir);
        return NULL;
    }

    dirp = CurrentWorkingDir();

    if(dirp == NULL)
    {
        LogMessage("Unable to access current directory\n");
        free(savedir);
        return NULL;
    }
    else
    {
        strncpy(buf, dirp, PATH_MAX_UTIL);
        buf[PATH_MAX_UTIL] = '\0';
    }

    if(chdir(savedir) < 0)
    {
        LogMessage("Can't change back to directory: %s\n", dir);
        free(savedir);                
        return NULL;
    }

    free(savedir);
    return (char *) buf;
}

// The following code was taken from Ethereal 0.10.4, with minor modification
if_info_t * if_info_new(char *name, char *description)
{
	if_info_t *if_info;

	if_info = (if_info_t *)malloc(sizeof (if_info_t));
	if_info->name = strdup(name);
	if (description == NULL) {
		if_info->description = NULL;
	}
	else {
		if_info->description = strdup(description);
	}
	if_info->addrs = NULL;
	if_info->next = NULL;

	return if_info;
}

#ifdef WIN32
/*
 * This will use "pcap_findalldevs()" if we have it, otherwise it'll
 * fall back on "pcap_lookupdev()".
 */
if_info_t * get_interface_list(int *err, char *err_str)
{
	//GList  *il = NULL;
	if_info_t *il = NULL;
	if_info_t *dev = NULL;
	wchar_t *names;
	char *win95names;
	char ascii_name[MAX_WIN_IF_NAME_LEN + 1];
	char ascii_desc[MAX_WIN_IF_NAME_LEN + 1];
	int i, j;

#ifdef HAVE_PCAP_FINDALLDEVS
	//if (p_pcap_findalldevs != NULL)
	return get_interface_list_findalldevs(err, err_str);
#endif

	/*
	 * In WinPcap, pcap_lookupdev is implemented by calling
	 * PacketGetAdapterNames.  According to the documentation
	 * I could find:
	 *
	 *	http://winpcap.polito.it/docs/man/html/Packet32_8c.html#a43
	 *
	 * this means that:
	 *
	 * On Windows OT (95, 98, Me), pcap_lookupdev returns a sequence
	 * of bytes consisting of:
	 *
	 *	a sequence of null-terminated ASCII strings (i.e., each
	 *	one is terminated by a single 0 byte), giving the names
	 *	of the interfaces;
	 *
	 *	an empty ASCII string (i.e., a single 0 byte);
	 *
	 *	a sequence of null-terminated ASCII strings, giving the
	 *	descriptions of the interfaces;
	 *
	 *	an empty ASCII string.
	 *
	 * On Windows NT (NT 4.0, W2K, WXP, W2K3, etc.), pcap_lookupdev
	 * returns a sequence of bytes consisting of:
	 *
	 *	a sequence of null-terminated double-byte Unicode strings
	 *	(i.e., each one consits of a sequence of double-byte
	 *	characters, terminated by a double-byte 0), giving the
	 *	names of the interfaces;
	 *
	 *	an empty Unicode string (i.e., a double 0 byte);
	 *
	 *	a sequence of null-terminated ASCII strings, giving the
	 *	descriptions of the interfaces;
	 *
	 *	an empty ASCII string.
	 *
	 * The Nth string in the first sequence is the name of the Nth
	 * adapter; the Nth string in the second sequence is the
	 * description of the Nth adapter.
	 */

	names = (wchar_t *)pcap_lookupdev(err_str);
	i = 0;

	if (names) {
		char* desc = 0;
		int desc_pos = 0;

		if (names[0]<256) {
			/*
			 * If names[0] is less than 256 it means the first
			 * byte is 0.  This implies that we are using Unicode
			 * characters.
			 */
			while (*(names+desc_pos) || *(names+desc_pos-1))
				desc_pos++;
			desc_pos++;	/* Step over the extra '\0' */
			desc = (char*)(names + desc_pos); /* cast *after* addition */

			while (names[i] != 0) {
				/*
				 * Copy the Unicode description to an ASCII
				 * string.
				 */
				j = 0;
				while (*desc != 0) {
					if (j < MAX_WIN_IF_NAME_LEN)
						ascii_desc[j++] = *desc;
					desc++;
				}
				ascii_desc[j] = '\0';
				desc++;

				/*
				 * Copy the Unicode name to an ASCII string.
				 */
				j = 0;
				while (names[i] != 0) {
					if (j < MAX_WIN_IF_NAME_LEN)
					ascii_name[j++] = (char) names[i++];
				}
				ascii_name[j] = '\0';
				i++;
				//il = g_list_append(il,
				//    if_info_new(ascii_name, ascii_desc));
				if(il == NULL) {
					il = if_info_new(ascii_name, ascii_desc);
					// Need to get IP and Netmask
				}
				else {
					for(dev = il; dev != NULL; dev = dev->next) {
						if(dev->next == NULL) {
							dev->next = if_info_new(ascii_name, ascii_desc);
							// Need to get IP and Netmask
							break;
						}
					}
				}
			}
		} else {
			/*
			 * Otherwise we are in Windows 95/98 and using ASCII
			 * (8-bit) characters.
			 */
			win95names=(char *)names;
			while (*(win95names+desc_pos) || *(win95names+desc_pos-1))
				desc_pos++;
			desc_pos++;	/* Step over the extra '\0' */
			desc = win95names + desc_pos;

			while (win95names[i] != '\0') {
				/*
				 * "&win95names[i]" points to the current
				 * interface name, and "desc" points to
				 * that interface's description.
				 */
				//il = g_list_append(il,
				//    if_info_new(&win95names[i], desc));
				if(il == NULL) {
					il = if_info_new(&win95names[i], desc);
					// Need to get IP and Netmask
				}
				else {
					for(dev = il; dev != NULL; dev = dev->next) {
						if(dev->next == NULL) {
							dev->next = if_info_new(&win95names[i], desc);
							// Need to get IP and Netmask
							break;
						}
					}
				}

				/*
				 * Skip to the next description.
				 */
				while (*desc != 0)
					desc++;
				desc++;

				/*
				 * Skip to the next name.
				 */
				while (win95names[i] != 0)
					i++;
				i++;
			}
		}
	}

	if (il == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = NO_INTERFACES_FOUND;
	}

	return il;
}

#else

if_info_t * get_interface_list(int *err, char *err_str)
{
#ifdef HAVE_PCAP_FINDALLDEVS
	return get_interface_list_findalldevs(err, err_str);
#else
	//GList  *il = NULL;
	if_info_t *il = NULL;
	if_info_t *dev = NULL;
	//gint    nonloopback_pos = 0;
	int     nonloopback_pos = 0;
	struct  ifreq *ifr, *last;
	struct  ifconf ifc;
	struct  ifreq ifrflags;
	struct  ifreq ifraddrs;
	struct  ifreq ifrnmask;
	int     sock = socket(AF_INET, SOCK_DGRAM, 0);
	//struct search_user_data user_data;
	pcap_t *pch;
	int len, lastlen;
	char *buf;
	if_info_t *if_info;

	if (sock < 0) {
		*err = CANT_GET_INTERFACE_LIST;
		sprintf(err_str, "Error opening socket: %s",
		    strerror(errno));
		return NULL;
	}

	/*
	 * This code came from: W. Richard Stevens: "UNIX Network Programming",
	 * Networking APIs: Sockets and XTI, Vol 1, page 434.
	 */
	lastlen = 0;
	len = 100 * sizeof(struct ifreq);
	for ( ; ; ) {
		buf = (char *)malloc(len);
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		memset (buf, 0, len);
		if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0) {
				sprintf(err_str,
					"SIOCGIFCONF ioctl error getting list of interfaces: %s",
					strerror(errno));
				goto fail;
			}
		} else {
			if ((unsigned) ifc.ifc_len < sizeof(struct ifreq)) {
				sprintf(err_str,
					"SIOCGIFCONF ioctl gave too small return buffer");
				goto fail;
			}
			if (ifc.ifc_len == lastlen)
				break;			/* success, len has not changed */
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof(struct ifreq);	/* increment */
		free(buf);
	}
	ifr = (struct ifreq *) ifc.ifc_req;
	last = (struct ifreq *) ((char *) ifr + ifc.ifc_len);
	while (ifr < last) {
		/*
		 * Skip addresses that begin with "dummy", or that include
		 * a ":" (the latter are Solaris virtuals).
		 */
		if (strncmp(ifr->ifr_name, "dummy", 5) == 0 ||
		    strchr(ifr->ifr_name, ':') != NULL)
			goto next;

		/*
		 * If we already have this interface name on the list,
		 * don't add it (SIOCGIFCONF returns, at least on
		 * BSD-flavored systems, one entry per interface *address*;
		 * if an interface has multiple addresses, we get multiple
		 * entries for it).
		 */
		//user_data.name = ifr->ifr_name;
		//user_data.found = FALSE;
		//g_list_foreach(il, search_for_if_cb, &user_data);
		//if (user_data.found)
		//	goto next;
		if(il != NULL) {
			for(dev = il; dev != NULL; dev = dev->next) {
				if(strcmp(dev->name, ifr->ifr_name) == 0) {
					goto next;
				}
			}
		}

		/*
		 * Get the interface flags.
		 */
		memset(&ifrflags, 0, sizeof ifrflags);
		strncpy(ifrflags.ifr_name, ifr->ifr_name,
		    sizeof ifrflags.ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
			if (errno == ENXIO)
				goto next;
			sprintf(err_str, "SIOCGIFFLAGS error getting flags for interface %s: %s",
			    ifr->ifr_name, strerror(errno));
			goto fail;
		}

		/*
		 * Skip interfaces that aren't up.
		 */
		if (!(ifrflags.ifr_flags & IFF_UP))
			goto next;

		/*
		 * Skip interfaces that we can't open with "libpcap".
		 * Open with the minimum packet size - it appears that the
		 * IRIX SIOCSNOOPLEN "ioctl" may fail if the capture length
		 * supplied is too large, rather than just truncating it.
		 */
		pch = pcap_open_live(ifr->ifr_name, MIN_PACKET_SIZE, 0, 0,
		    err_str);
		if (pch == NULL)
			goto next;
		pcap_close(pch);

		// Get the IP Address and Netmask
		memset(&ifraddrs, 0, sizeof(ifraddrs));
		strncpy(ifraddrs.ifr_name, ifr->ifr_name, sizeof(ifraddrs.ifr_name));
		if(ioctl(sock, SIOCGIFADDR, (char *)&ifraddrs) < 0) {
			goto next;
		}
		memset(&ifrnmask, 0, sizeof(ifrnmask));
		strncpy(ifrnmask.ifr_name, ifr->ifr_name, sizeof(ifrnmask.ifr_name));
		if(ioctl(sock, SIOCGIFNETMASK, (char *)&ifrnmask) < 0) {
			goto next;
		}

		/*
		 * If it's a loopback interface, add it at the end of the
		 * list, otherwise add it after the last non-loopback
		 * interface, so all loopback interfaces go at the end - we
		 * don't want a loopback interface to be the default capture
		 * device unless there are no non-loopback devices.
		 */
		if_info = if_info_new(ifr->ifr_name, NULL);
		if_info->addrs = (if_addr_t *)malloc(sizeof(if_addr_t));
		memcpy((struct in_addr *)&if_info->addrs->ip, (struct in_addr *)&((struct sockaddr_in *)&ifraddrs.ifr_addr)->sin_addr, sizeof(struct in_addr));
		memcpy((struct in_addr *)&if_info->addrs->netmask, (struct in_addr *)&((struct sockaddr_in *)&ifrnmask.ifr_addr)->sin_addr, sizeof(struct in_addr));
		if_info->addrs->next = NULL;
		if ((ifrflags.ifr_flags & IFF_LOOPBACK) ||
		    strncmp(ifr->ifr_name, "lo", 2) == 0) {
			//il = g_list_append(il, if_info);
			if(il == NULL) {
				il = if_info;
			}
			else {
				for(dev = il; dev != NULL; dev = dev->next) {
					if(dev->next == NULL) {
						dev->next = if_info;
						break;
					}
				}
			}
		}
		else {
			//il = g_list_insert(il, if_info, nonloopback_pos);
			if(nonloopback_pos == 0) {
				if_info->next = il;
				il = if_info;
			}
			else {
				dev = il;
				for(int x = 1; x < nonloopback_pos; x++) {
					dev = dev->next;
				}
				if_info->next = dev->next;
				dev->next = if_info;
			}
			/*
			 * Insert the next non-loopback interface after this
			 * one.
			 */
			nonloopback_pos++;
		}

	next:
#ifdef HAVE_SA_LEN
		ifr = (struct ifreq *) ((char *) ifr +
		    (ifr->ifr_addr.sa_len > sizeof(ifr->ifr_addr) ?
			ifr->ifr_addr.sa_len : sizeof(ifr->ifr_addr)) +
		    IFNAMSIZ);
#else
		ifr = (struct ifreq *) ((char *) ifr + sizeof(struct ifreq));
#endif
	}

#ifdef linux
	/*
	 * OK, maybe we have support for the "any" device, to do a cooked
	 * capture on all interfaces at once.
	 * Try opening it and, if that succeeds, add it to the end of
	 * the list of interfaces.
	 */
	pch = pcap_open_live("any", MIN_PACKET_SIZE, 0, 0, err_str);
	if (pch != NULL) {
		/*
		 * It worked; we can use the "any" device.
		 */
		if_info = if_info_new("any",
		    "Pseudo-device that captures on all interfaces");
		if_info->addrs = NULL;
		//il = g_list_insert(il, if_info, -1);
		if_info->next = il;
		il = if_info;
		pcap_close(pch);
	}
#endif

	free(ifc.ifc_buf);
	close(sock);

	if (il == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = NO_INTERFACES_FOUND;
	}
	return il;

fail:
	if (il != NULL)
		free_interface_list(il);
	free(ifc.ifc_buf);
	close(sock);
	*err = CANT_GET_INTERFACE_LIST;
	return NULL;
#endif /* HAVE_PCAP_FINDALLDEVS */
}
#endif

#ifdef HAVE_PCAP_FINDALLDEVS
if_info_t * get_interface_list_findalldevs(int *err, char *err_str)
{
	//GList  *il = NULL;
	if_info_t *il = NULL;
	if_info_t *count = NULL;
	pcap_if_t *alldevs, *dev;
	pcap_addr_t *addr;
	if_info_t *if_info;
	if_addr_t *if_addr = NULL;

	if (pcap_findalldevs(&alldevs, err_str) == -1) {
		*err = CANT_GET_INTERFACE_LIST;
		return NULL;
	}

	if (alldevs == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = NO_INTERFACES_FOUND;
		return NULL;
	}

	for (dev = alldevs; dev != NULL; dev = dev->next) {
		if_info = if_info_new(dev->name, dev->description);
		for(addr = dev->addresses; addr != NULL; addr = addr->next) {
			if(addr->addr->sa_family == AF_INET) {
				if_addr = if_info->addrs;
				if(if_addr == NULL) {
					if_info->addrs = (if_addr_t *)malloc(sizeof(if_addr_t));
					if_addr = if_info->addrs;
				}
				else {
					while(if_addr->next != NULL) {
						if_addr = if_addr->next;
					}
					if_addr->next = (if_addr_t *)malloc(sizeof(if_addr_t));
					if_addr = if_addr->next;
				}
				memcpy((struct in_addr *)&if_addr->ip, (struct in_addr *)&((struct sockaddr_in *)addr->addr)->sin_addr, sizeof(struct in_addr));
				if(addr->netmask != NULL) {
					memcpy((struct in_addr *)&if_addr->netmask, (struct in_addr *)&((struct sockaddr_in *)addr->netmask)->sin_addr, sizeof(struct in_addr));
				}
				if_addr->next = NULL;
			}
		}
		//il = g_list_append(il, if_info);
		if(il == NULL) {
			il = if_info;
		}
		else {
			for(count = il; count != NULL; count = count->next) {
				if(count->next == NULL) {
					count->next = if_info;
					break;
				}
			}
		}
	}
	pcap_freealldevs(alldevs);

	return il;
}
#endif /* HAVE_PCAP_FINDALLDEVS */

void free_interface_list(if_info_t *if_list)
{
	if_info_t *dev = NULL;
	if_info_t *prevdev = NULL;
	if_addr_t *addrs = NULL;
	if_addr_t *prevaddrs = NULL;

	//g_list_foreach(if_list, free_if_cb, NULL);
	//g_list_free(if_list);
	dev = if_list;
	while(dev != NULL) {
		if(dev->name != NULL) {
			free(dev->name);
		}
		if(dev->description != NULL) {
			free(dev->description);
		}
		addrs = dev->addrs;
		while(addrs != NULL) {
			prevaddrs = addrs;
			addrs = addrs->next;
			free(prevaddrs);
		}
		prevdev = dev;
		dev = dev->next;
		free(prevdev);
	}
}

