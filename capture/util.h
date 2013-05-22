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

#ifndef __UTIL_H__
#define __UTIL_H__

#ifndef WIN32
#include <sys/time.h>
#include <sys/types.h>
#endif /* !WIN32 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRLCPY
#include "strlcpyu.h"
#endif

#ifndef WIN32
#include <sys/ioctl.h>
#endif /* !WIN32 */

#include "neti.h"

#define CANT_GET_INTERFACE_LIST 0	/* error getting list */
#define NO_INTERFACES_FOUND     1	/* list is empty */

int DisplayBanner();
int strip(char *);
void ReadPacketsFromFile();
void GoDaemon();
void PrintError(const char *);
void ErrorMessage(const char *, ...);
void LogMessage(const char *, ...);
void FatalError(const char *, ...);
void FatalPrintError(const char *);
void CreatePidFile(const char *);
void SetUidGid(void);
void SetChroot(const char *, const char **);
char *CurrentWorkingDir(void);
char *GetAbsolutePath(const char *dir);
if_info_t * get_interface_list(int *err, char *err_str);
void free_interface_list(if_info_t *if_list);
#ifdef HAVE_PCAP_FINDALLDEVS
if_info_t * get_interface_list_findalldevs(int *err, char *err_str);
#endif

#endif /*__UTIL_H__*/
