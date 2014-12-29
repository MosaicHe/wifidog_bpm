/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/


#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"

/** @internal
 The different configuration options */
typedef enum {
	xBpmwifiapi,
	xRes,
	xGwid,
	x24g,
	x5g,
	xRurl,
	xTwifiuser,
	xSelfmedia,
	xMacwhitelist,
	xMacblacklist,
	xUrlwhitelist,
	xUrlblacklist,
	xGeturl,
	xChangelist,
	oBadOpt,
} XCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	XCodes xcodes;
} xwords[] = {
	{"bpmwifiapi",  	xBpmwifiapi},
	{"res",				xRes },
	{"gw_id",			xGwid },
	{"24g",				x24g},
	{"5g", 				x5g},
	{"reurl", 			xRurl},
	{"macwhitelist",	xMacwhitelist},
	{"macblaclist", 	xMacblacklist},
	{"twifire",			xTwifiuser},
	{"serfmedia", 		xSelfmedia},
	{"urlwhitelist", 	xUrlwhitelist},
	{"urlblacklist", 	xUrlblacklist},
	{"geturl", 			xGeturl},
	{"changelist", 		xChangelist},
		
	{ NULL,				oBadOpt }
};

struct wInfo
{
	int channel;
	char ssid1[32];
	char ssid2[32];
	char ssid3[32];
	char ssid4[32];
};


struct rInfo{
	char* fw[16];
	char* sn[18];
	struct wInfo w_24g;
//	struct wInfo w_5g;
} g_rInfo={
	"1.0",
	"bpm7620a00001",
		{1, "OPEN_AP",0,0,0},
};

char * getcontent(const char *url)
{
	char buf[MAX_BUF], *content, *tmp;
	int sockfd, done, nfds;
	ssize_t	numbytes;
	size_t totalbytes;
	
	fd_set			readfds;
	struct timeval		timeout;
	
	t_auth_serv	*auth_server = NULL;
	auth_server = get_auth_server();
	
	
	sockfd = connect_auth_server();
	if (sockfd == -1) {
		/* Could not connect to any auth server */
		return NULL;
	}
	
	snprintf(buf, (sizeof(buf) - 1),
		"GET %s HTTP/1.0\r\n"
		"User-Agent: WiFiDog %s\r\n"
		"Host: %s\r\n"
		"\r\n",
		url,
		VERSION,
		auth_server->authserv_hostname
	);
	debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", buf);
	 
	
	send(sockfd, buf, strlen(buf), 0);
	debug(LOG_DEBUG, "Reading response");
	numbytes = totalbytes = 0;
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second is as good a timeout as any */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return NULL;
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return NULL;
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return NULL;
		}
	} while (!done);

	close(sockfd);

	buf[totalbytes] = '\0';
	if ((tmp = strstr(buf, "\r\n\r\n"))) {
		content = safe_strdup(tmp+4);
	}
	else
	{
		content = safe_strdup(buf);
	}
	
	
	return content;
}


void getRconf()
{
	char *content = NULL, *url = NULL, *cmd = NULL, *tmp = NULL;
	int rc;
	FILE *conffile;
	t_auth_serv	*auth_server = get_auth_server();
	s_config *config = config_get_config();
	
	
	safe_asprintf(&url, "%s%sactoin=getRconf&gw_id=%s&fw=%s&sn=%s&storge=%s", 
				auth_server->authserv_path, 
				auth_server->authserv_api_script_path_fragment, 
				config_get_config()->gw_id, 
 				g_rInfo.fw,
 				g_rInfo.sn,
 				"no"
 				);
	content = getcontent(url);
	if(url){
		free(url);
		url = NULL;
	}
	if(!content){
		return ;
	}
	
	debug(LOG_DEBUG, "get conf file[%s]", content);
	return ;
}





