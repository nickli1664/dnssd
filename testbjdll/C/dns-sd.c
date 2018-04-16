/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2002-2008 Apple Inc. All rights reserved.
 *
 * Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple Computer, Inc.
 * ("Apple") in consideration of your agreement to the following terms, and your
 * use, installation, modification or redistribution of this Apple software
 * constitutes acceptance of these terms.  If you do not agree with these terms,
 * please do not use, install, modify or redistribute this Apple software.
 *
 * In consideration of your agreement to abide by the following terms, and subject
 * to these terms, Apple grants you a personal, non-exclusive license, under Apple's
 * copyrights in this original Apple software (the "Apple Software"), to use,
 * reproduce, modify and redistribute the Apple Software, with or without
 * modifications, in source and/or binary forms; provided that if you redistribute
 * the Apple Software in its entirety and without modifications, you must retain
 * this notice and the following text and disclaimers in all such redistributions of
 * the Apple Software.  Neither the name, trademarks, service marks or logos of
 * Apple Computer, Inc. may be used to endorse or promote products derived from the
 * Apple Software without specific prior written permission from Apple.  Except as
 * expressly stated in this notice, no other rights or licenses, express or implied,
 * are granted by Apple herein, including but not limited to any patent rights that
 * may be infringed by your derivative works or by other works in which the Apple
 * Software may be incorporated.
 *
 * The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
 * COMBINATION WITH YOUR PRODUCTS.
 *
 * IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
 * OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT
 * (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Formatting notes:
 * This code follows the "Whitesmiths style" C indentation rules. Plenty of discussion
 * on C indentation can be found on the web, such as <http://www.kafejo.com/komp/1tbs.htm>,
 * but for the sake of brevity here I will say just this: Curly braces are not syntactially
 * part of an "if" statement; they are the beginning and ending markers of a compound statement;
 * therefore common sense dictates that if they are part of a compound statement then they
 * should be indented to the same level as everything else in that compound statement.
 * Indenting curly braces at the same level as the "if" implies that curly braces are
 * part of the "if", which is false. (This is as misleading as people who write "char* x,y;"
 * thinking that variables x and y are both of type "char*" -- and anyone who doesn't
 * understand why variable y is not of type "char*" just proves the point that poor code
 * layout leads people to unfortunate misunderstandings about how the C language really works.)

To build this tool, copy and paste the following into a command line:

OS X:
gcc dns-sd.c -o dns-sd

POSIX systems:
gcc dns-sd.c -o dns-sd -I../mDNSShared -ldns_sd

Windows:
cl dns-sd.c -I../mDNSShared -DNOT_HAVE_GETOPT ws2_32.lib ..\mDNSWindows\DLL\Release\dnssd.lib
(may require that you run a Visual Studio script such as vsvars32.bat first)
*/

// For testing changes to dnssd_clientstub.c, uncomment this line and the code will be compiled
// with an embedded copy of the client stub instead of linking the system library version at runtime.
// This also useful to work around link errors when you're working on an older version of Mac OS X,
// and trying to build a newer version of the "dns-sd" command which uses new API entry points that
// aren't in the system's /usr/lib/libSystem.dylib.
//#define TEST_NEW_CLIENTSTUB 1

// When building mDNSResponder for Mac OS X 10.4 and earlier, /usr/lib/libSystem.dylib is built using its own private
// copy of dnssd_clientstub.c, which is old and doesn't have all the entry points defined in the latest version, so
// when we're building dns-sd.c on Mac OS X 10.4 or earlier, we automatically set TEST_NEW_CLIENTSTUB so that we'll
// embed a copy of the latest dnssd_clientstub.c instead of trying to link to the incomplete version in libSystem.dylib
#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ <= 1040
#define TEST_NEW_CLIENTSTUB 1
#endif

#include <ctype.h>
#include <stdio.h>			// For stdout, stderr
#include <stdlib.h>			// For exit()
#include <string.h>			// For strlen(), strcpy()
#include <errno.h>			// For errno, EINTR
#include <time.h>
#include <sys/types.h>		// For u_char
#define _DEMO Demo

#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <Iphlpapi.h>
	#include <process.h>
	typedef int        pid_t;
	#define getpid     _getpid
	#define strcasecmp _stricmp
	#define snprintf   _snprintf
	static const char kFilePathSep = '\\';
	#ifndef HeapEnableTerminationOnCorruption
	#     define HeapEnableTerminationOnCorruption (HEAP_INFORMATION_CLASS)1
	#endif
	#if !defined(IFNAMSIZ)
	 #define IFNAMSIZ 16
    #endif
	#define if_nametoindex if_nametoindex_win
	#define if_indextoname if_indextoname_win

	typedef PCHAR (WINAPI * if_indextoname_funcptr_t)(ULONG index, PCHAR name);
	typedef ULONG (WINAPI * if_nametoindex_funcptr_t)(PCSTR name);

	unsigned if_nametoindex_win(const char *ifname)
		{
		HMODULE library;
		unsigned index = 0;

		// Try and load the IP helper library dll
		if ((library = LoadLibrary(TEXT("Iphlpapi")) ) != NULL )
			{
			if_nametoindex_funcptr_t if_nametoindex_funcptr;

			// On Vista and above there is a Posix like implementation of if_nametoindex
			if ((if_nametoindex_funcptr = (if_nametoindex_funcptr_t) GetProcAddress(library, "if_nametoindex")) != NULL )
				{
				index = if_nametoindex_funcptr(ifname);
				}

			FreeLibrary(library);
			}

		return index;
		}

	char * if_indextoname_win( unsigned ifindex, char *ifname)
		{
		HMODULE library;
		char * name = NULL;

		// Try and load the IP helper library dll
		if ((library = LoadLibrary(TEXT("Iphlpapi")) ) != NULL )
			{
			if_indextoname_funcptr_t if_indextoname_funcptr;

			// On Vista and above there is a Posix like implementation of if_indextoname
			if ((if_indextoname_funcptr = (if_indextoname_funcptr_t) GetProcAddress(library, "if_indextoname")) != NULL )
				{
				name = if_indextoname_funcptr(ifindex, ifname);
				}

			FreeLibrary(library);
			}

		return name;
		}

#else
	#include <unistd.h>			// For getopt() and optind
	#include <netdb.h>			// For getaddrinfo()
	#include <sys/time.h>		// For struct timeval
	#include <sys/socket.h>		// For AF_INET
	#include <netinet/in.h>		// For struct sockaddr_in()
	#include <arpa/inet.h>		// For inet_addr()
	#include <net/if.h>			// For if_nametoindex()
	static const char kFilePathSep = '/';
#endif

#if (TEST_NEW_CLIENTSTUB && !defined(__APPLE_API_PRIVATE))
#define __APPLE_API_PRIVATE 1
#endif

#include "dns_sd.h"

#include "ClientCommon.h"

#if TEST_NEW_CLIENTSTUB
#include "../mDNSShared/dnssd_ipc.c"
#include "../mDNSShared/dnssd_clientlib.c"
#include "../mDNSShared/dnssd_clientstub.c"
#endif

// The "+0" is to cope with the case where _DNS_SD_H is defined but empty (e.g. on Mac OS X 10.4 and earlier)
#if _DNS_SD_H+0 >= 116
#define HAS_NAT_PMP_API 1
#define HAS_ADDRINFO_API 1
#else
#define kDNSServiceFlagsReturnIntermediates 0
#endif

//*************************************************************************************************************
// Globals

typedef union { unsigned char b[2]; unsigned short NotAnInteger; } Opaque16;

static int operation;
static uint32_t opinterface = kDNSServiceInterfaceIndexAny;
static DNSServiceRef client    = NULL;
static DNSServiceRef client_pa = NULL;	// DNSServiceRef for RegisterProxyAddressRecord
static DNSServiceRef sc1, sc2, sc3;		// DNSServiceRefs for kDNSServiceFlagsShareConnection testing

static int num_printed;
static char addtest = 0;
static DNSRecordRef record = NULL;
static char myhinfoW[14] = "\002PC\012Windows XP";
static char myhinfoX[ 9] = "\003Mac\004OS X";
static char updatetest[3] = "\002AA";
static char bigNULL[8192];	// 8K is maximum rdata we support

// Note: the select() implementation on Windows (Winsock2) fails with any timeout much larger than this
#define LONG_TIME 100000000

static volatile int stopNow = 0;
static volatile int timeOut = LONG_TIME;

//*************************************************************************************************************
// Supporting Utility Functions

static uint16_t GetRRType(const char *s)
	{
	if      (!strcasecmp(s, "A"       )) return(kDNSServiceType_A);
	else if (!strcasecmp(s, "NS"      )) return(kDNSServiceType_NS);
	else if (!strcasecmp(s, "MD"      )) return(kDNSServiceType_MD);
	else if (!strcasecmp(s, "MF"      )) return(kDNSServiceType_MF);
	else if (!strcasecmp(s, "CNAME"   )) return(kDNSServiceType_CNAME);
	else if (!strcasecmp(s, "SOA"     )) return(kDNSServiceType_SOA);
	else if (!strcasecmp(s, "MB"      )) return(kDNSServiceType_MB);
	else if (!strcasecmp(s, "MG"      )) return(kDNSServiceType_MG);
	else if (!strcasecmp(s, "MR"      )) return(kDNSServiceType_MR);
	else if (!strcasecmp(s, "NULL"    )) return(kDNSServiceType_NULL);
	else if (!strcasecmp(s, "WKS"     )) return(kDNSServiceType_WKS);
	else if (!strcasecmp(s, "PTR"     )) return(kDNSServiceType_PTR);
	else if (!strcasecmp(s, "HINFO"   )) return(kDNSServiceType_HINFO);
	else if (!strcasecmp(s, "MINFO"   )) return(kDNSServiceType_MINFO);
	else if (!strcasecmp(s, "MX"      )) return(kDNSServiceType_MX);
	else if (!strcasecmp(s, "TXT"     )) return(kDNSServiceType_TXT);
	else if (!strcasecmp(s, "RP"      )) return(kDNSServiceType_RP);
	else if (!strcasecmp(s, "AFSDB"   )) return(kDNSServiceType_AFSDB);
	else if (!strcasecmp(s, "X25"     )) return(kDNSServiceType_X25);
	else if (!strcasecmp(s, "ISDN"    )) return(kDNSServiceType_ISDN);
	else if (!strcasecmp(s, "RT"      )) return(kDNSServiceType_RT);
	else if (!strcasecmp(s, "NSAP"    )) return(kDNSServiceType_NSAP);
	else if (!strcasecmp(s, "NSAP_PTR")) return(kDNSServiceType_NSAP_PTR);
	else if (!strcasecmp(s, "SIG"     )) return(kDNSServiceType_SIG);
	else if (!strcasecmp(s, "KEY"     )) return(kDNSServiceType_KEY);
	else if (!strcasecmp(s, "PX"      )) return(kDNSServiceType_PX);
	else if (!strcasecmp(s, "GPOS"    )) return(kDNSServiceType_GPOS);
	else if (!strcasecmp(s, "AAAA"    )) return(kDNSServiceType_AAAA);
	else if (!strcasecmp(s, "LOC"     )) return(kDNSServiceType_LOC);
	else if (!strcasecmp(s, "NXT"     )) return(kDNSServiceType_NXT);
	else if (!strcasecmp(s, "EID"     )) return(kDNSServiceType_EID);
	else if (!strcasecmp(s, "NIMLOC"  )) return(kDNSServiceType_NIMLOC);
	else if (!strcasecmp(s, "SRV"     )) return(kDNSServiceType_SRV);
	else if (!strcasecmp(s, "ATMA"    )) return(kDNSServiceType_ATMA);
	else if (!strcasecmp(s, "NAPTR"   )) return(kDNSServiceType_NAPTR);
	else if (!strcasecmp(s, "KX"      )) return(kDNSServiceType_KX);
	else if (!strcasecmp(s, "CERT"    )) return(kDNSServiceType_CERT);
	else if (!strcasecmp(s, "A6"      )) return(kDNSServiceType_A6);
	else if (!strcasecmp(s, "DNAME"   )) return(kDNSServiceType_DNAME);
	else if (!strcasecmp(s, "SINK"    )) return(kDNSServiceType_SINK);
	else if (!strcasecmp(s, "OPT"     )) return(kDNSServiceType_OPT);
	else if (!strcasecmp(s, "TKEY"    )) return(kDNSServiceType_TKEY);
	else if (!strcasecmp(s, "TSIG"    )) return(kDNSServiceType_TSIG);
	else if (!strcasecmp(s, "IXFR"    )) return(kDNSServiceType_IXFR);
	else if (!strcasecmp(s, "AXFR"    )) return(kDNSServiceType_AXFR);
	else if (!strcasecmp(s, "MAILB"   )) return(kDNSServiceType_MAILB);
	else if (!strcasecmp(s, "MAILA"   )) return(kDNSServiceType_MAILA);
	else if (!strcasecmp(s, "ANY"     )) return(kDNSServiceType_ANY);
	else                                 return(atoi(s));
	}

#if HAS_NAT_PMP_API | HAS_ADDRINFO_API
static DNSServiceProtocol GetProtocol(const char *s)
	{
	if      (!strcasecmp(s, "v4"      )) return(kDNSServiceProtocol_IPv4);
	else if (!strcasecmp(s, "v6"      )) return(kDNSServiceProtocol_IPv6);
	else if (!strcasecmp(s, "v4v6"    )) return(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6);
	else if (!strcasecmp(s, "v6v4"    )) return(kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6);
	else if (!strcasecmp(s, "udp"     )) return(kDNSServiceProtocol_UDP);
	else if (!strcasecmp(s, "tcp"     )) return(kDNSServiceProtocol_TCP);
	else if (!strcasecmp(s, "udptcp"  )) return(kDNSServiceProtocol_UDP | kDNSServiceProtocol_TCP);
	else if (!strcasecmp(s, "tcpudp"  )) return(kDNSServiceProtocol_UDP | kDNSServiceProtocol_TCP);
	else                                 return(atoi(s));
	}
#endif

//*************************************************************************************************************
// Sample callback functions for each of the operation types

static void printtimestamp(void)
	{
	struct tm tm;
	int ms;
#ifdef _WIN32
	SYSTEMTIME sysTime;
	time_t uct = time(NULL);
	tm = *localtime(&uct);
	GetLocalTime(&sysTime);
	ms = sysTime.wMilliseconds;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	localtime_r((time_t*)&tv.tv_sec, &tm);
	ms = tv.tv_usec/1000;
#endif
	printf("%2d:%02d:%02d.%03d  ", tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
	}

#define DomainMsg(X) (((X) & kDNSServiceFlagsDefault) ? "(Default)" : \
                      ((X) & kDNSServiceFlagsAdd)     ? "Added"     : "Removed")

#define MAX_LABELS 128

static void DNSSD_API enum_reply(DNSServiceRef sdref, const DNSServiceFlags flags, uint32_t ifIndex,
	DNSServiceErrorType errorCode, const char *replyDomain, void *context)
	{
	DNSServiceFlags partialflags = flags & ~(kDNSServiceFlagsMoreComing | kDNSServiceFlagsAdd | kDNSServiceFlagsDefault);
	int labels = 0, depth = 0, i, initial = 0;
	char text[64];
	const char *label[MAX_LABELS];
	
	(void)sdref;        // Unused
	(void)ifIndex;      // Unused
	(void)context;      // Unused

	// 1. Print the header
	if (num_printed++ == 0) printf("Timestamp     Recommended %s domain\n", operation == 'E' ? "Registration" : "Browsing");
	printtimestamp();
	if (errorCode)
		printf("Error code %d\n", errorCode);
	else if (!*replyDomain)
		printf("Error: No reply domain\n");
	else
		{
		printf("%-10s", DomainMsg(flags));
		printf("%-8s", (flags & kDNSServiceFlagsMoreComing) ? "(More)" : "");
		if (partialflags) printf("Flags: %4X  ", partialflags);
		else printf("             ");
		
		// 2. Count the labels
		while (replyDomain && *replyDomain && labels < MAX_LABELS)
			{
			label[labels++] = replyDomain;
			replyDomain = GetNextLabel(replyDomain, text);
			}
		
		// 3. Decide if we're going to clump the last two or three labels (e.g. "apple.com", or "nicta.com.au")
		if      (labels >= 3 && replyDomain - label[labels-1] <= 3 && label[labels-1] - label[labels-2] <= 4) initial = 3;
		else if (labels >= 2 && replyDomain - label[labels-1] <= 4) initial = 2;
		else initial = 1;
		labels -= initial;
	
		// 4. Print the initial one-, two- or three-label clump
		for (i=0; i<initial; i++)
			{
			GetNextLabel(label[labels+i], text);
			if (i>0) printf(".");
			printf("%s", text);
			}
		printf("\n");
	
		// 5. Print the remainder of the hierarchy
		for (depth=0; depth<labels; depth++)
			{
			printf("                                             ");
			for (i=0; i<=depth; i++) printf("- ");
			GetNextLabel(label[labels-1-depth], text);
			printf("> %s\n", text);
			}
		}

	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	}

static int CopyLabels(char *dst, const char *lim, const char **srcp, int labels)
	{
	const char *src = *srcp;
	while (*src != '.' || --labels > 0)
		{
		if (*src == '\\') *dst++ = *src++;	// Make sure "\." doesn't confuse us
		if (!*src || dst >= lim) return -1;
		*dst++ = *src++;
		if (!*src || dst >= lim) return -1;
		}
	*dst++ = 0;
	*srcp = src + 1;	// skip over final dot
	return 0;
	}

static void DNSSD_API zonedata_resolve(DNSServiceRef sdref, const DNSServiceFlags flags, uint32_t ifIndex, DNSServiceErrorType errorCode,
	const char *fullname, const char *hosttarget, uint16_t opaqueport, uint16_t txtLen, const unsigned char *txt, void *context)
	{
	union { uint16_t s; u_char b[2]; } port = { opaqueport };
	uint16_t PortAsNumber = ((uint16_t)port.b[0]) << 8 | port.b[1];

	const char *p = fullname;
	char n[kDNSServiceMaxDomainName];
	char t[kDNSServiceMaxDomainName];

	const unsigned char *max = txt + txtLen;

	(void)sdref;        // Unused
	(void)ifIndex;      // Unused
	(void)context;      // Unused

	//if (!(flags & kDNSServiceFlagsAdd)) return;
	if (errorCode) { printf("Error code %d\n", errorCode); return; }

	if (CopyLabels(n, n + kDNSServiceMaxDomainName, &p, 3)) return;		// Fetch name+type
	p = fullname;
	if (CopyLabels(t, t + kDNSServiceMaxDomainName, &p, 1)) return;		// Skip first label
	if (CopyLabels(t, t + kDNSServiceMaxDomainName, &p, 2)) return;		// Fetch next two labels (service type)

	if (num_printed++ == 0)
		{
		printf("\n");
		printf("; To direct clients to browse a different domain, substitute that domain in place of '@'\n");
		printf("%-47s PTR     %s\n", "lb._dns-sd._udp", "@");
		printf("\n");
		printf("; In the list of services below, the SRV records will typically reference dot-local Multicast DNS names.\n");
		printf("; When transferring this zone file data to your unicast DNS server, you'll need to replace those dot-local\n");
		printf("; names with the correct fully-qualified (unicast) domain name of the target host offering the service.\n");
		}

	printf("\n");
	printf("%-47s PTR     %s\n", t, n);
	printf("%-47s SRV     0 0 %d %s ; Replace with unicast FQDN of target host\n", n, PortAsNumber, hosttarget);
	printf("%-47s TXT    ", n);

	while (txt < max)
		{
		const unsigned char *const end = txt + 1 + txt[0];
		txt++;		// Skip over length byte
		printf(" \"");
		while (txt<end)
			{
			if (*txt == '\\' || *txt == '\"') printf("\\");
			printf("%c", *txt++);
			}
		printf("\"");
		}
	printf("\n");

	DNSServiceRefDeallocate(sdref);
	free(context);

	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	}

static void DNSSD_API zonedata_browse(DNSServiceRef sdref, const DNSServiceFlags flags, uint32_t ifIndex, DNSServiceErrorType errorCode,
	const char *replyName, const char *replyType, const char *replyDomain, void *context)
	{
	DNSServiceRef *newref;

	(void)sdref;        // Unused
	(void)context;      // Unused

	if (!(flags & kDNSServiceFlagsAdd)) return;
	if (errorCode) { printf("Error code %d\n", errorCode); return; }

	newref = malloc(sizeof(*newref));
	*newref = client;
	DNSServiceResolve(newref, kDNSServiceFlagsShareConnection, ifIndex, replyName, replyType, replyDomain, zonedata_resolve, newref);
	}

static void DNSSD_API browse_reply(DNSServiceRef sdref, const DNSServiceFlags flags, uint32_t ifIndex, DNSServiceErrorType errorCode,
	const char *replyName, const char *replyType, const char *replyDomain, void *context)
	{
	char *op = (flags & kDNSServiceFlagsAdd) ? "Add" : "Rmv";
	(void)sdref;        // Unused
	(void)context;      // Unused
	if (num_printed++ == 0) printf("Timestamp     A/R Flags if %-25s %-25s %s\n", "Domain", "Service Type", "Instance Name");
	printtimestamp();
	if (errorCode) printf("Error code %d\n", errorCode);
	else printf("%s%6X%3d %-25s %-25s %s\n", op, flags, ifIndex, replyDomain, replyType, replyName);
	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);

	// To test selective cancellation of operations of shared sockets,
	// cancel the current operation when we've got a multiple of five results
	//if (operation == 'S' && num_printed % 5 == 0) DNSServiceRefDeallocate(sdref);
	}

static void ShowTXTRecord(uint16_t txtLen, const unsigned char *txtRecord)
	{
	const unsigned char *ptr = txtRecord;
	const unsigned char *max = txtRecord + txtLen;
	while (ptr < max)
		{
		const unsigned char *const end = ptr + 1 + ptr[0];
		if (end > max) { printf("<< invalid data >>"); break; }
		if (++ptr < end) printf(" ");   // As long as string is non-empty, begin with a space
		while (ptr<end)
			{
			// We'd like the output to be shell-friendly, so that it can be copied and pasted unchanged into a "dns-sd -R" command.
			// However, this is trickier than it seems. Enclosing a string in double quotes doesn't necessarily make it
			// shell-safe, because shells still expand variables like $foo even when they appear inside quoted strings.
			// Enclosing a string in single quotes is better, but when using single quotes even backslash escapes are ignored,
			// meaning there's simply no way to represent a single quote (or apostrophe) inside a single-quoted string.
			// The only remaining solution is not to surround the string with quotes at all, but instead to use backslash
			// escapes to encode spaces and all other known shell metacharacters.
			// (If we've missed any known shell metacharacters, please let us know.)
			// In addition, non-printing ascii codes (0-31) are displayed as \xHH, using a two-digit hex value.
			// Because '\' is itself a shell metacharacter (the shell escape character), it has to be escaped as "\\" to survive
			// the round-trip to the shell and back. This means that a single '\' is represented here as EIGHT backslashes:
			// The C compiler eats half of them, resulting in four appearing in the output.
			// The shell parses those four as a pair of "\\" sequences, passing two backslashes to the "dns-sd -R" command.
			// The "dns-sd -R" command interprets this single "\\" pair as an escaped literal backslash. Sigh.
			if (strchr(" &;`'\"|*?~<>^()[]{}$", *ptr)) printf("\\");
			if      (*ptr == '\\') printf("\\\\\\\\");
			else if (*ptr >= ' ' ) printf("%c",        *ptr);
			else                   printf("\\\\x%02X", *ptr);
			ptr++;
			}
		}
	}

static void DNSSD_API resolve_reply(DNSServiceRef sdref, const DNSServiceFlags flags, uint32_t ifIndex, DNSServiceErrorType errorCode,
	const char *fullname, const char *hosttarget, uint16_t opaqueport, uint16_t txtLen, const unsigned char *txtRecord, void *context)
	{
	union { uint16_t s; u_char b[2]; } port = { opaqueport };
	uint16_t PortAsNumber = ((uint16_t)port.b[0]) << 8 | port.b[1];

	(void)sdref;        // Unused
	(void)ifIndex;      // Unused
	(void)context;      // Unused

	printtimestamp();
	if (errorCode) printf("Error code %d\n", errorCode);
	else
		{
		printf("%s can be reached at %s:%u (interface %d)", fullname, hosttarget, PortAsNumber, ifIndex);
		if (flags) printf(" Flags: %X", flags);
		// Don't show degenerate TXT records containing nothing but a single empty string
		if (txtLen > 1) { printf("\n"); ShowTXTRecord(txtLen, txtRecord); }
		printf("\n");
		}

	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	}

static void myTimerCallBack(void)
	{
	DNSServiceErrorType err = kDNSServiceErr_Unknown;

	switch (operation)
		{
		case 'A':
			{
			switch (addtest)
				{
				case 0: printf("Adding Test HINFO record\n");
						err = DNSServiceAddRecord(client, &record, 0, kDNSServiceType_HINFO, sizeof(myhinfoW), &myhinfoW[0], 0);
						addtest = 1;
						break;
				case 1: printf("Updating Test HINFO record\n");
						err = DNSServiceUpdateRecord(client, record, 0, sizeof(myhinfoX), &myhinfoX[0], 0);
						addtest = 2;
						break;
				case 2: printf("Removing Test HINFO record\n");
						err = DNSServiceRemoveRecord(client, record, 0);
						addtest = 0;
						break;
				}
			}
			break;

		case 'U':
			{
			if (updatetest[1] != 'Z') updatetest[1]++;
			else                      updatetest[1] = 'A';
			updatetest[0] = 3 - updatetest[0];
			updatetest[2] = updatetest[1];
			printtimestamp();
			printf("Updating Test TXT record to %c\n", updatetest[1]);
			err = DNSServiceUpdateRecord(client, NULL, 0, 1+updatetest[0], &updatetest[0], 0);
			}
			break;

		case 'N':
			{
			printf("Adding big NULL record\n");
			err = DNSServiceAddRecord(client, &record, 0, kDNSServiceType_NULL, sizeof(bigNULL), &bigNULL[0], 0);
			if (err) printf("Failed: %d\n", err); else printf("Succeeded\n");
			timeOut = LONG_TIME;
			}
			break;
		}

	if (err != kDNSServiceErr_NoError)
		{
		fprintf(stderr, "DNSService add/update/remove failed %ld\n", (long int)err);
		stopNow = 1;
		}
	}

static void DNSSD_API reg_reply(DNSServiceRef sdref, const DNSServiceFlags flags, DNSServiceErrorType errorCode,
	const char *name, const char *regtype, const char *domain, void *context)
	{
	(void)sdref;    // Unused
	(void)flags;    // Unused
	(void)context;  // Unused

	printtimestamp();
	printf("Got a reply for service %s.%s%s: ", name, regtype, domain);

	if (errorCode == kDNSServiceErr_NoError)
		{
		if (flags & kDNSServiceFlagsAdd) printf("Name now registered and active\n"); 
		else printf("Name registration removed\n"); 
		if (operation == 'A' || operation == 'U' || operation == 'N') timeOut = 5;
		}
	else if (errorCode == kDNSServiceErr_NameConflict)
		{
		printf("Name in use, please choose another\n");
		exit(-1);
		}
	else
		printf("Error %d\n", errorCode);

	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	}

// Output the wire-format domainname pointed to by rd
static int snprintd(char *p, int max, const unsigned char **rd)
	{
	const char *const buf = p;
	const char *const end = p + max;
	while (**rd) { p += snprintf(p, end-p, "%.*s.", **rd, *rd+1); *rd += 1 + **rd; }
	*rd += 1;	// Advance over the final zero byte
	return(p-buf);
	}

static void DNSSD_API qr_reply(DNSServiceRef sdref, const DNSServiceFlags flags, uint32_t ifIndex, DNSServiceErrorType errorCode,
	const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *context)
	{
	char *op = (flags & kDNSServiceFlagsAdd) ? "Add" : "Rmv";
	const unsigned char *rd  = rdata;
	const unsigned char *end = (const unsigned char *) rdata + rdlen;
	char rdb[1000] = "", *p = rdb;
	int unknowntype = 0;

	(void)sdref;    // Unused
	(void)flags;    // Unused
	(void)ifIndex;  // Unused
	(void)ttl;      // Unused
	(void)context;  // Unused

	if (num_printed++ == 0) printf("Timestamp     A/R Flags if %-30s%4s%4s Rdata\n", "Name", "T", "C");
	printtimestamp();

	if (!errorCode)
		{
		switch (rrtype)
			{
			case kDNSServiceType_A:
				snprintf(rdb, sizeof(rdb), "%d.%d.%d.%d", rd[0], rd[1], rd[2], rd[3]);
				break;
	
			case kDNSServiceType_NS:
			case kDNSServiceType_CNAME:
			case kDNSServiceType_PTR:
			case kDNSServiceType_DNAME:
				p += snprintd(p, sizeof(rdb), &rd);
				break;
	
			case kDNSServiceType_SOA:
				p += snprintd(p, rdb + sizeof(rdb) - p, &rd);		// mname
				p += snprintf(p, rdb + sizeof(rdb) - p, " ");
				p += snprintd(p, rdb + sizeof(rdb) - p, &rd);		// rname
				p += snprintf(p, rdb + sizeof(rdb) - p, " Ser %d Ref %d Ret %d Exp %d Min %d",
					ntohl(((uint32_t*)rd)[0]), ntohl(((uint32_t*)rd)[1]), ntohl(((uint32_t*)rd)[2]), ntohl(((uint32_t*)rd)[3]), ntohl(((uint32_t*)rd)[4]));
				break;
	
			case kDNSServiceType_AAAA:
				snprintf(rdb, sizeof(rdb), "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
					rd[0x0], rd[0x1], rd[0x2], rd[0x3], rd[0x4], rd[0x5], rd[0x6], rd[0x7],
					rd[0x8], rd[0x9], rd[0xA], rd[0xB], rd[0xC], rd[0xD], rd[0xE], rd[0xF]);
				break;
	
			case kDNSServiceType_SRV:
				p += snprintf(p, rdb + sizeof(rdb) - p, "%d %d %d ",	// priority, weight, port
					ntohs(*(unsigned short*)rd), ntohs(*(unsigned short*)(rd+2)), ntohs(*(unsigned short*)(rd+4)));
				rd += 6;
				p += snprintd(p, rdb + sizeof(rdb) - p, &rd);			// target host
				break;
	
			default : snprintf(rdb, sizeof(rdb), "%d bytes%s", rdlen, rdlen ? ":" : ""); unknowntype = 1; break;
			}
		}

	printf("%s%6X%3d %-30s%4d%4d %s", op, flags, ifIndex, fullname, rrtype, rrclass, rdb);
	if (unknowntype) while (rd < end) printf(" %02X", *rd++);
	if (errorCode)
		{
		if (errorCode == kDNSServiceErr_NoSuchRecord) printf("No Such Record");
		else                                          printf("Error code %d", errorCode);
		}
	printf("\n");

	if (operation == 'C')
		if (flags & kDNSServiceFlagsAdd)
			DNSServiceReconfirmRecord(flags, ifIndex, fullname, rrtype, rrclass, rdlen, rdata);

	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	}

#if HAS_NAT_PMP_API
static void DNSSD_API port_mapping_create_reply(DNSServiceRef sdref, DNSServiceFlags flags, uint32_t ifIndex, DNSServiceErrorType errorCode, uint32_t publicAddress, uint32_t protocol, uint16_t privatePort, uint16_t publicPort, uint32_t ttl, void *context)
	{
	(void)sdref;       // Unused
	(void)context;     // Unused
	(void)flags;       // Unused
	
	if (num_printed++ == 0) printf("Timestamp     if   %-20s %-15s %-15s %-15s %-6s\n", "External Address", "Protocol", "Internal Port", "External Port", "TTL");
	printtimestamp();
	if (errorCode && errorCode != kDNSServiceErr_DoubleNAT) printf("Error code %d\n", errorCode);
	else
		{
		const unsigned char *digits = (const unsigned char *)&publicAddress;
		char                 addr[256];

		snprintf(addr, sizeof(addr), "%d.%d.%d.%d", digits[0], digits[1], digits[2], digits[3]);
		printf("%-4d %-20s %-15d %-15d %-15d %-6d%s\n", ifIndex, addr, protocol, ntohs(privatePort), ntohs(publicPort), ttl, errorCode == kDNSServiceErr_DoubleNAT ? " Double NAT" : "");
		}
	fflush(stdout);
	}
#endif

#if HAS_ADDRINFO_API
static void DNSSD_API addrinfo_reply(DNSServiceRef sdref, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *hostname, const struct sockaddr *address, uint32_t ttl, void *context)
	{
	char *op = (flags & kDNSServiceFlagsAdd) ? "Add" : "Rmv";
	char addr[256] = "";
	(void) sdref;
	(void) context;
	
	if (num_printed++ == 0) printf("Timestamp     A/R Flags if %-25s %-44s %s\n", "Hostname", "Address", "TTL");
	printtimestamp();

	if (address && address->sa_family == AF_INET)
		{
		const unsigned char *b = (const unsigned char *) &((struct sockaddr_in *)address)->sin_addr;
		snprintf(addr, sizeof(addr), "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
		}
	else if (address && address->sa_family == AF_INET6)
		{
		char if_name[IFNAMSIZ];		// Older Linux distributions don't define IF_NAMESIZE
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)address;
		const unsigned char       *b  = (const unsigned char *      )&s6->sin6_addr;
		if (!if_indextoname(s6->sin6_scope_id, if_name))
			snprintf(if_name, sizeof(if_name), "<%d>", s6->sin6_scope_id);
		snprintf(addr, sizeof(addr), "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X%%%s",
				b[0x0], b[0x1], b[0x2], b[0x3], b[0x4], b[0x5], b[0x6], b[0x7],
				b[0x8], b[0x9], b[0xA], b[0xB], b[0xC], b[0xD], b[0xE], b[0xF], if_name);
		}

	printf("%s%6X%3d %-25s %-44s %d", op, flags, interfaceIndex, hostname, addr, ttl);
	if (errorCode)
		{
		if (errorCode == kDNSServiceErr_NoSuchRecord) printf("   No Such Record");
		else                                          printf("   Error code %d", errorCode);
		}
	printf("\n");

	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	}
#endif

//*************************************************************************************************************
// The main test function

static void HandleEvents(void)
	{
	int dns_sd_fd  = client    ? DNSServiceRefSockFD(client   ) : -1;
	int dns_sd_fd2 = client_pa ? DNSServiceRefSockFD(client_pa) : -1;
	int nfds = dns_sd_fd + 1;
	fd_set readfds;
	struct timeval tv;
	int result;
	
	if (dns_sd_fd2 > dns_sd_fd) nfds = dns_sd_fd2 + 1;

	while (!stopNow)
		{
		// 1. Set up the fd_set as usual here.
		// This example client has no file descriptors of its own,
		// but a real application would call FD_SET to add them to the set here
		FD_ZERO(&readfds);

		// 2. Add the fd for our client(s) to the fd_set
		if (client   ) FD_SET(dns_sd_fd , &readfds);
		if (client_pa) FD_SET(dns_sd_fd2, &readfds);

		// 3. Set up the timeout.
		tv.tv_sec  = timeOut;
		tv.tv_usec = 0;

		result = select(nfds, &readfds, (fd_set*)NULL, (fd_set*)NULL, &tv);
		if (result > 0)
			{
			DNSServiceErrorType err = kDNSServiceErr_NoError;
			if      (client    && FD_ISSET(dns_sd_fd , &readfds)) err = DNSServiceProcessResult(client   );
			else if (client_pa && FD_ISSET(dns_sd_fd2, &readfds)) err = DNSServiceProcessResult(client_pa);
			if (err) { fprintf(stderr, "DNSServiceProcessResult returned %d\n", err); stopNow = 1; }
			}
		else if (result == 0)
			myTimerCallBack();
		else
			{
			printf("select() returned %d errno %d %s\n", result, errno, strerror(errno));
			if (errno != EINTR) stopNow = 1;
			}
		}
	}

static int getfirstoption(int argc, char **argv, const char *optstr, int *pOptInd)
// Return the recognized option in optstr and the option index of the next arg.
#if NOT_HAVE_GETOPT
	{
	int i;
	for (i=1; i < argc; i++)
		{
		if (argv[i][0] == '-' && &argv[i][1] && 
			 NULL != strchr(optstr, argv[i][1]))
			{
			*pOptInd = i + 1;
			return argv[i][1];
			}
		}
	return -1;
	}
#else
	{
	int o = getopt(argc, (char *const *)argv, optstr);
	*pOptInd = optind;
	return o;
	}
#endif

static void DNSSD_API MyRegisterRecordCallback(DNSServiceRef service, DNSRecordRef rec, const DNSServiceFlags flags,
    DNSServiceErrorType errorCode, void *context)
	{
	char *name = (char *)context;
	
	(void)service;	// Unused
	(void)rec;	// Unused
	(void)flags;	// Unused
	
	printtimestamp();
	printf("Got a reply for record %s: ", name);

	switch (errorCode)
		{
		case kDNSServiceErr_NoError:      printf("Name now registered and active\n"); break;
		case kDNSServiceErr_NameConflict: printf("Name in use, please choose another\n"); exit(-1);
		default:                          printf("Error %d\n", errorCode); break;
		}
	if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
	// DNSServiceRemoveRecord(service, rec, 0); to test record removal
	}

static unsigned long getip(const char *const name)
	{
	unsigned long ip = 0;
	struct addrinfo hints;
	struct addrinfo *addrs = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	
	if (getaddrinfo(name, NULL, &hints, &addrs) == 0)
		{
		ip = ((struct sockaddr_in*) addrs->ai_addr)->sin_addr.s_addr;
		}

	if (addrs)
		{
		freeaddrinfo(addrs);
		}

	return(ip);
	}

static DNSServiceErrorType RegisterProxyAddressRecord(DNSServiceRef sdref, const char *host, const char *ip)
	{
	// Call getip() after the call DNSServiceCreateConnection().
	// On the Win32 platform, WinSock must be initialized for getip() to succeed.
	// Any DNSService* call will initialize WinSock for us, so we make sure
	// DNSServiceCreateConnection() is called before getip() is.
	unsigned long addr = getip(ip);
	return(DNSServiceRegisterRecord(sdref, &record, kDNSServiceFlagsUnique, opinterface, host,
		kDNSServiceType_A, kDNSServiceClass_IN, sizeof(addr), &addr, 240, MyRegisterRecordCallback, (void*)host));
	// Note, should probably add support for creating proxy AAAA records too, one day
	}

#define HexVal(X) ( ((X) >= '0' && (X) <= '9') ? ((X) - '0'     ) :  \
					((X) >= 'A' && (X) <= 'F') ? ((X) - 'A' + 10) :  \
					((X) >= 'a' && (X) <= 'f') ? ((X) - 'a' + 10) : 0)

#define HexPair(P) ((HexVal((P)[0]) << 4) | HexVal((P)[1]))

static DNSServiceErrorType RegisterService(DNSServiceRef *sdref,
	const char *nam, const char *typ, const char *dom, const char *host, const char *port, int argc, char **argv)
	{
	DNSServiceFlags flags = 0;
	uint16_t PortAsNumber = atoi(port);
	Opaque16 registerPort = { { PortAsNumber >> 8, PortAsNumber & 0xFF } };
	unsigned char txt[2048] = "";
	unsigned char *ptr = txt;
	int i;
	
	if (nam[0] == '.' && nam[1] == 0) nam = "";   // We allow '.' on the command line as a synonym for empty string
	if (dom[0] == '.' && dom[1] == 0) dom = "";   // We allow '.' on the command line as a synonym for empty string
	
	printf("Registering Service %s.%s%s%s", nam[0] ? nam : "<<Default>>", typ, dom[0] ? "." : "", dom);
	if (host && *host) printf(" host %s", host);
	printf(" port %s", port);

	if (argc)
		{
		for (i = 0; i < argc; i++)
			{
			const char *p = argv[i];
			*ptr = 0;
			while (*p && *ptr < 255 && ptr + 1 + *ptr < txt+sizeof(txt))
				{
				if      (p[0] != '\\' || p[1] == 0)                       { ptr[++*ptr] = *p;           p+=1; }
				else if (p[1] == 'x' && isxdigit(p[2]) && isxdigit(p[3])) { ptr[++*ptr] = HexPair(p+2); p+=4; }
				else                                                      { ptr[++*ptr] = p[1];         p+=2; }
				}
			ptr += 1 + *ptr;
			}
		printf(" TXT");
		ShowTXTRecord(ptr-txt, txt);
		}
	printf("\n");
	
	//flags |= kDNSServiceFlagsAllowRemoteQuery;
	//flags |= kDNSServiceFlagsNoAutoRename;
	
	return(DNSServiceRegister(sdref, flags, opinterface, nam, typ, dom, host, registerPort.NotAnInteger, (uint16_t) (ptr-txt), txt, reg_reply, NULL));
	}

#define TypeBufferSize 80
static char *gettype(char *buffer, char *typ)
	{
	if (!typ || !*typ || (typ[0] == '.' && typ[1] == 0)) typ = "_http._tcp";
	if (!strchr(typ, '.')) { snprintf(buffer, TypeBufferSize, "%s._tcp", typ); typ = buffer; }
	return(typ);
	}


__declspec(dllexport) int zhucebj(int raopp, int airplayp)
{
	DNSServiceErrorType err;

#ifdef _DEMO
	Demo :
	{

#define kRaopPort	raopp
#define kAirplayPort	airplayp

		static DNSServiceRef airplayRef = NULL;
		static DNSServiceRef raopRef = NULL;

		Opaque16 AirplayPort = { { kAirplayPort >> 8, kAirplayPort & 0xFF } };
		Opaque16 RaopPort = { { kRaopPort >> 8, kRaopPort & 0xFF } };

		printf("enterDemo\n");

		static const char AirplayTXT[] =
			"\x1A" "deviceid=40:8d:5c:e3:54:59" \
			"\x18" "features=0x527FFFF7,0x1E" \
			//nick add 20180118
			"\x0A" "flags=0x44" \
			"\x11" "model=AppleTV3,2C" \
			"\x2A" "pk=2f1fff2fff5fbf2ffffff1464f1fff3ffffffe0" \
			"\x0E" "srcvers=220.68" \
			"\x04" "ch=2";
			//"\x18" "features=0x5A7FFFF7,0x1E";


		static const char RaopTXT[] =
			"\x0E" "am=AppleTV3,2C" \
			/* "\x04" "ch=2" \ */
			"\x0A" "cn=0,1,2,3" \
			"\x07" "da=true" \
			"\x08" "et=0,3,5" \
			"\x12" "ft=0x527FFFF7,0x1E" \
			/* "\x12" "ft=0x5A7FFFF7,0x1E" \ */
			"\x08" "md=0,1,2" \
			"\x06" "tp=UDP" \
			"\x08" "vn=65537" \
			"\x09" "vs=220.68" \
			"\x04" "vv=2" \
			"\x07" "sf=0x44" \
			"\x2A" "pk=2f1fff2fff5fbf2ffffff1464f1fff3ffffffe0";
			/* "\x43" "pk=85e139fff33bd22d244f527b5776a5c6688c44c902255a118dbb0be3b64d861f"; */
			/* "\x09" "txtvers=1"; */


		err = DNSServiceRegister(&airplayRef, 0, opinterface, "Nicktest", "_airplay._tcp.", "", NULL, AirplayPort.NotAnInteger, 0, NULL, reg_reply, NULL);
		if (!err) err = DNSServiceUpdateRecord(airplayRef, NULL, 0, sizeof(AirplayTXT) - 1, AirplayTXT, 0);

		err = DNSServiceRegister(&raopRef, 0, opinterface, "408D5CE35459@Nicktest", "_raop._tcp.", "", NULL, RaopPort.NotAnInteger, 0, NULL, reg_reply, NULL);
		if (!err) err = DNSServiceUpdateRecord(raopRef, NULL, 0, sizeof(RaopTXT) - 1, RaopTXT, 0);

		while (1)getchar();

		return 0;
	}
#endif
}



// Note: The C preprocessor stringify operator ('#') makes a string from its argument, without macro expansion
// e.g. If "version" is #define'd to be "4", then STRINGIFY_AWE(version) will return the string "version", not "4"
// To expand "version" to its value before making the string, use STRINGIFY(version) instead
#define STRINGIFY_ARGUMENT_WITHOUT_EXPANSION(s) #s
#define STRINGIFY(s) STRINGIFY_ARGUMENT_WITHOUT_EXPANSION(s)

// NOT static -- otherwise the compiler may optimize it out
// The "@(#) " pattern is a special prefix the "what" command looks for
const char VersionString_SCCS[] = "@(#) dns-sd " STRINGIFY(mDNSResponderVersion) " (" __DATE__ " " __TIME__ ")";

#if _BUILDING_XCODE_PROJECT_
// If the process crashes, then this string will be magically included in the automatically-generated crash log
const char *__crashreporter_info__ = VersionString_SCCS + 5;
asm(".desc ___crashreporter_info__, 0x10");
#endif
