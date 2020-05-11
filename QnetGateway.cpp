/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
 *   Copyright (C) 2017-2018 by Thomas Early N7TAE
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* by KI4LKF, N7TAE */
/*
   QnetGateway is a dstar G2 gateway, using irc routing
       adapted from the OpenG2 G2 gateway
   Version 2.61 or higher will use ONLY the irc mechanism of routing
     and it will NOT use any local Postgres databases or any TRUST(s)
*/

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <csignal>
#include <future>
#include <exception>
#include <thread>
#include <chrono>

#include "IRCDDB.h"
#include "Utilities.h"
#include "QnetGateway.h"
#include "QnetConfigure.h"
#include "QnetDB.h"

#define VERSION "QnetIcomGateway-511"

#ifndef CFG_DIR
#define CFG_DIR "/usr/local/etc"
#endif

static std::atomic<bool> keep_running(true);
static std::atomic<unsigned short> G2_COUNTER_OUT(0);
static unsigned short OLD_REPLY_SEQ = 0;
static unsigned short NEW_REPLY_SEQ = 0;

/* signal catching function */
static void sigCatch(int signum)
{
	/* do NOT do any serious work here */
	if ((signum == SIGTERM) || (signum == SIGINT))
		keep_running = false;

	return;
}

void CQnetGateway::set_dest_rptr(const char mod, std::string &call)
{
	std::list<CLink> linklist;
	if (qnDB.FindLS(mod, linklist))
		return;

	auto count = linklist.size();
	if (count != 1)
		printf("set_dest_rptr() returned %d link sets\n", int(count));
	if (0 == count)
		return;

	call.assign(linklist.front().callsign);
}

/* compute checksum */
void CQnetGateway::calcPFCS(unsigned char *packet, int len)
{
	const unsigned short crc_tabccitt[256] = {
		0x0000,0x1189,0x2312,0x329b,0x4624,0x57ad,0x6536,0x74bf,0x8c48,0x9dc1,0xaf5a,0xbed3,0xca6c,0xdbe5,0xe97e,0xf8f7,
		0x1081,0x0108,0x3393,0x221a,0x56a5,0x472c,0x75b7,0x643e,0x9cc9,0x8d40,0xbfdb,0xae52,0xdaed,0xcb64,0xf9ff,0xe876,
		0x2102,0x308b,0x0210,0x1399,0x6726,0x76af,0x4434,0x55bd,0xad4a,0xbcc3,0x8e58,0x9fd1,0xeb6e,0xfae7,0xc87c,0xd9f5,
		0x3183,0x200a,0x1291,0x0318,0x77a7,0x662e,0x54b5,0x453c,0xbdcb,0xac42,0x9ed9,0x8f50,0xfbef,0xea66,0xd8fd,0xc974,
		0x4204,0x538d,0x6116,0x709f,0x0420,0x15a9,0x2732,0x36bb,0xce4c,0xdfc5,0xed5e,0xfcd7,0x8868,0x99e1,0xab7a,0xbaf3,
		0x5285,0x430c,0x7197,0x601e,0x14a1,0x0528,0x37b3,0x263a,0xdecd,0xcf44,0xfddf,0xec56,0x98e9,0x8960,0xbbfb,0xaa72,
		0x6306,0x728f,0x4014,0x519d,0x2522,0x34ab,0x0630,0x17b9,0xef4e,0xfec7,0xcc5c,0xddd5,0xa96a,0xb8e3,0x8a78,0x9bf1,
		0x7387,0x620e,0x5095,0x411c,0x35a3,0x242a,0x16b1,0x0738,0xffcf,0xee46,0xdcdd,0xcd54,0xb9eb,0xa862,0x9af9,0x8b70,
		0x8408,0x9581,0xa71a,0xb693,0xc22c,0xd3a5,0xe13e,0xf0b7,0x0840,0x19c9,0x2b52,0x3adb,0x4e64,0x5fed,0x6d76,0x7cff,
		0x9489,0x8500,0xb79b,0xa612,0xd2ad,0xc324,0xf1bf,0xe036,0x18c1,0x0948,0x3bd3,0x2a5a,0x5ee5,0x4f6c,0x7df7,0x6c7e,
		0xa50a,0xb483,0x8618,0x9791,0xe32e,0xf2a7,0xc03c,0xd1b5,0x2942,0x38cb,0x0a50,0x1bd9,0x6f66,0x7eef,0x4c74,0x5dfd,
		0xb58b,0xa402,0x9699,0x8710,0xf3af,0xe226,0xd0bd,0xc134,0x39c3,0x284a,0x1ad1,0x0b58,0x7fe7,0x6e6e,0x5cf5,0x4d7c,
		0xc60c,0xd785,0xe51e,0xf497,0x8028,0x91a1,0xa33a,0xb2b3,0x4a44,0x5bcd,0x6956,0x78df,0x0c60,0x1de9,0x2f72,0x3efb,
		0xd68d,0xc704,0xf59f,0xe416,0x90a9,0x8120,0xb3bb,0xa232,0x5ac5,0x4b4c,0x79d7,0x685e,0x1ce1,0x0d68,0x3ff3,0x2e7a,
		0xe70e,0xf687,0xc41c,0xd595,0xa12a,0xb0a3,0x8238,0x93b1,0x6b46,0x7acf,0x4854,0x59dd,0x2d62,0x3ceb,0x0e70,0x1ff9,
		0xf78f,0xe606,0xd49d,0xc514,0xb1ab,0xa022,0x92b9,0x8330,0x7bc7,0x6a4e,0x58d5,0x495c,0x3de3,0x2c6a,0x1ef1,0x0f78
	};
	unsigned short crc_dstar_ffff = 0xffff;
	short int low, high;
	unsigned short tmp;

	switch (len) {
		case 56:
			low = 15;
			high = 54;
			break;
		case 58:
			low = 17;
			high = 56;
			break;
		default:
			return;
	}

	for (unsigned short int i = low; i < high ; i++) {
		unsigned short short_c = 0x00ff & (unsigned short)packet[i];
		tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
		crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
	}
	crc_dstar_ffff =  ~crc_dstar_ffff;
	tmp = crc_dstar_ffff;

	if (len == 56) {
		packet[54] = (unsigned char)(crc_dstar_ffff & 0xff);
		packet[55] = (unsigned char)((tmp >> 8) & 0xff);
	} else {
		packet[56] = (unsigned char)(crc_dstar_ffff & 0xff);
		packet[57] = (unsigned char)((tmp >> 8) & 0xff);
	}

	return;
}

void CQnetGateway::UnpackCallsigns(const std::string &str, std::set<std::string> &set, const std::string &delimiters)
{
	std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);	// Skip delimiters at beginning.
	std::string::size_type pos = str.find_first_of(delimiters, lastPos);	// Find first non-delimiter.

	while (std::string::npos != pos || std::string::npos != lastPos) {
		std::string element = str.substr(lastPos, pos-lastPos);
		if (element.length()>=3 && element.length()<=6) {
			ToUpper(element);
			element.resize(CALL_SIZE, ' ');
			set.insert(element);	// Found a token, add it to the list.
		} else
			fprintf(stderr, "found bad callsign in list: %s\n", str.c_str());
		lastPos = str.find_first_not_of(delimiters, pos);	// Skip delimiters.
		pos = str.find_first_of(delimiters, lastPos);	// Find next non-delimiter.
	}
}

void CQnetGateway::PrintCallsigns(const std::string &key, const std::set<std::string> &set)
{
	printf("%s = [", key.c_str());
	for (auto it=set.begin(); it!=set.end(); it++) {
		if (it != set.begin())
			printf(",");
		printf("%s", (*it).c_str());
	}
	printf("]\n");
}

/* process configuration file */
bool CQnetGateway::read_config(char *cfgFile)
{
	CQnetConfigure cfg;
	if (cfg.Initialize(cfgFile))
		return true;

	// ircddb
	const std::string estr("");
	std::string path("ircddb_");
	if (!cfg.KeyExists(path+"login")) {
		fprintf(stderr, "You must specify your lisensed callsign in ircddb.login\n");
		return true;
	}
	if (cfg.GetValue(path+"login", estr, owner, 3, 6))
		return true;
	OWNER = owner;
	ToLower(owner);
	ToUpper(OWNER);
	printf("OWNER=[%s]\n", OWNER.c_str());
	OWNER.resize(CALL_SIZE, ' ');
	if (cfg.GetValue(path+"host", estr, ircddb.ip, 3, MAXHOSTNAMELEN))
		return true;
	int iport;
	cfg.GetValue(path+"port", estr, iport, 1000, 65535);
	ircddb.port = iport;
	if(cfg.GetValue(path+"password", estr, irc_pass, 0, 512))
		return true;

	// gateway
	path.assign("gateway_");
	cfg.GetValue(path+"header_regen",   estr, bool_regen_header);
	cfg.GetValue(path+"send_qrgs_maps", estr, bool_send_qrgs);
	cfg.GetValue(path+"external_ip",    estr, g2_external.ip,    7, IP_SIZE);
	cfg.GetValue(path+"external_port",  estr, iport,          1024,   65535);
	g2_external.port = iport;
	cfg.GetValue(path+"internal_ip",    estr, g2_internal.ip,    7, IP_SIZE);
	cfg.GetValue(path+"internal_port",  estr, iport,          1024,   65535);
	g2_internal.port = iport;
	path.append("find_route");	// this has to be the last gateway_ key value
	if (cfg.KeyExists(path)) {
		std::string csv;
		cfg.GetValue(path, estr, csv, 0, 10240);
		UnpackCallsigns(csv, findRoute);
		PrintCallsigns(path, findRoute);
	}

	// modules
	for (short int m=0; m<3; m++) {
		path.assign("module_");
		path.append(1, 'a'+m);
		std::string type;
		if (cfg.KeyExists(path)) {
			cfg.GetValue(path, estr, type, 1, 16);
			rptr.mod[m].defined = true;
			avalidmodule = m;
			if (0 == type.compare("icom")) {
				rptr.mod[m].package_version = VERSION;
			} else {
				printf("module type '%s' is invalid\n", type.c_str());
				return true;
			}
			path.append(1, '_');
			cfg.GetValue(path+"ip",           type, rptr.mod[m].portip.ip,        7,   IP_SIZE);
			cfg.GetValue(path+"port",         type, iport,                     1024,     65535);
			rptr.mod[m].portip.port = iport;
			cfg.GetValue(path+"frequency",    type, rptr.mod[m].frequency,      0.0,    1.0e12);
			cfg.GetValue(path+"offset",       type, rptr.mod[m].offset,     -1.0e12,    1.0e12);
			cfg.GetValue(path+"range",        type, rptr.mod[m].range,          0.0, 1609344.0);
			cfg.GetValue(path+"agl",          type, rptr.mod[m].agl,            0.0,    1000.0);
			cfg.GetValue("gateway_latitude",  estr, rptr.mod[m].latitude,     -90.0,      90.0);
			cfg.GetValue("gateway_longitude", estr, rptr.mod[m].longitude,   -180.0,     180.0);
			cfg.GetValue("gateway_desc1",     estr, rptr.mod[m].desc1,            0,        20);
			cfg.GetValue("gateway_desc2",     estr, rptr.mod[m].desc2,            0,        20);
			cfg.GetValue("gateway_url",       estr, rptr.mod[m].url,              0,        80);
			// truncate strings
			if (rptr.mod[m].desc1.length() > 20)
				rptr.mod[m].desc1.resize(20);
			if (rptr.mod[m].desc2.length() > 20)
				rptr.mod[m].desc2.resize(20);
			// make the long description for the log
			if (rptr.mod[m].desc1.length())
				rptr.mod[m].desc = rptr.mod[m].desc1 + ' ';
			rptr.mod[m].desc += rptr.mod[m].desc2;
		} else
			rptr.mod[m].defined = false;
	}
	if (rptr.mod[0].defined==false && rptr.mod[1].defined==false && rptr.mod[2].defined==false) {
		printf("No modules defined!\n");
		return true;
	} else {
		std::string addr;
		int port;
		for (int i=0; i<3; i++) {
			if (rptr.mod[i].defined) {
				if (addr.size()) {
					if (addr.compare(rptr.mod[i].portip.ip) || port!=rptr.mod[i].portip.port) {
						fprintf(stderr, "all defined ICOM modules must have the same IP address and port number!\n");
						return true;
					}
				} else {
					addr = rptr.mod[i].portip.ip;
					port = rptr.mod[i].portip.port;
				}
			}
		}
	}

	// APRS
	path.assign("aprs_");
	cfg.GetValue(path+"enable",   estr, bool_send_aprs);
	cfg.GetValue(path+"host",     estr, rptr.aprs.ip,        7, MAXHOSTNAMELEN);
	cfg.GetValue(path+"port",     estr, iport,           10000,          65535);
	rptr.aprs.port = iport;
	cfg.GetValue(path+"interval", estr, rptr.aprs_interval, 40,           1000);
	cfg.GetValue(path+"filter",   estr, rptr.aprs_filter,    0,            512);

	// log
	path.assign("log_");
	cfg.GetValue(path+"qso",   estr, bool_qso_details);
	cfg.GetValue(path+"irc",   estr, bool_irc_debug);
	cfg.GetValue(path+"dtmf",  estr, bool_dtmf_debug);
	cfg.GetValue(path+"debug", estr, bool_log_debug);

	// file
	path.assign("file_");
	cfg.GetValue(path+"echotest",    estr, echotest_dir, 2, FILENAME_MAX);
	cfg.GetValue(path+"dtmf",        estr, dtmf_dir,     2, FILENAME_MAX);
	cfg.GetValue(path+"qnvoicefile", estr, qnvoicefile,  2, FILENAME_MAX);

	// link
	path.assign("link_");
	cfg.GetValue(path+"port", estr, iport,        16000, 65535);
	g2_link.port = iport;
	cfg.GetValue(path+"ip",   estr, g2_link.ip,       7,    15);

	// timing
	path.assign("timing_timeout_");
	cfg.GetValue(path+"echotest",   estr, echotest_rec_timeout,    1, 10);
	cfg.GetValue(path+"voicemail",  estr, voicemail_rec_timeout,   1, 10);
	cfg.GetValue(path+"remote_g2",  estr, from_remote_g2_timeout,  1, 10);
	cfg.GetValue(path+"local_rptr", estr, from_local_rptr_timeout, 1, 10);
	path.assign("timing_play_");
	cfg.GetValue(path+"wait",  estr, play_wait,  1, 10);
	cfg.GetValue(path+"delay", estr, play_delay, 9, 25);

	path.assign("dash_");
	cfg.GetValue(path+"sql_filename", estr, DASH_SQL_NAME, 2, 32);
	cfg.GetValue(path+"show_order", estr, DASH_SHOW_ORDER, 2, 16);
	showLastHeard = (DASH_SHOW_ORDER.npos==DASH_SHOW_ORDER.find("LH")) ? false : true;

	return false;
}

// Create ports
int CQnetGateway::open_port(const SPORTIP &pip)
{
	struct sockaddr_in sin;

	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (0 > sock) {
		printf("Failed to create socket on %s:%d, errno=%d, %s\n", pip.ip.c_str(), pip.port, errno, strerror(errno));
		return -1;
	}
	fcntl(sock, F_SETFL, O_NONBLOCK);

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(pip.port);
	sin.sin_addr.s_addr = inet_addr(pip.ip.c_str());

	int reuse = 1;
	if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1) {
		printf("Cannot set the UDP socket (port %u) option, err: %d, %s\n", pip.port, errno, strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) != 0) {
		printf("Failed to bind %s:%d, errno=%d, %s\n", pip.ip.c_str(), pip.port, errno, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

/* receive data from the irc server and save it */
void CQnetGateway::GetIRCDataThread()
{
	std::string user, rptr, gateway, ipaddr;
	struct sigaction act;

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		printf("GetIRCDataThread: sigaction-TERM failed, error=%d\n", errno);
		keep_running = false;
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		printf("GetIRCDataThread: sigaction-INT failed, error=%d\n", errno);
		keep_running = false;
		return;
	}
	if (sigaction(SIGPIPE, &act, 0) != 0) {
		printf("GetIRCDataThread: sigaction-PIPE failed, error=%d\n", errno);
		keep_running = false;
		return;
	}

	short threshold = 0;
	bool not_announced[3];
	for (int i=0; i<3; i++)
		not_announced[i] = this->rptr.mod[i].defined;	// announce to all modules that are defined!
	bool is_quadnet = (0 == ircddb.ip.compare("rr.openquad.net"));
	bool doFind = true;
	while (keep_running) {
		int rc = ii->getConnectionState();
		if (rc > 5 && rc < 8 && is_quadnet) {
			char ch = '\0';
			if (not_announced[0])
				ch = 'A';
			else if (not_announced[1])
				ch = 'B';
			else if (not_announced[2])
				ch = 'C';
			if (ch) {
				// we need to announce, but can we?
				struct stat sbuf;
				if (stat(qnvoicefile.c_str(), &sbuf)) {
					// yes, there is no qnvoicefile, so create it
					FILE *fp = fopen(qnvoicefile.c_str(), "w");
					if (fp) {
						fprintf(fp, "%c_connected2network.dat_WELCOME_TO_QUADNET", ch);
						fclose(fp);
						not_announced[ch - 'A'] = false;
					} else
						fprintf(stderr, "could not open %s\n", qnvoicefile.c_str());
				}
			}
			if (doFind) {
				printf("Finding Routes for...\n");
				for (auto it=findRoute.begin(); it!=findRoute.end(); it++) {
					std::this_thread::sleep_for(std::chrono::milliseconds(800));
					printf("\t'%s'\n", it->c_str());
					ii->findUser(*it);
				}
				doFind = false;
			}
		}

		if (++threshold >= 100) {
			if ((rc == 0) || (rc == 10)) {
				printf("irc status=%d, probable disconnect...\n", rc);
			} else {
				printf("irc status=%d, probable connect...\n", rc);
			}
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	printf("GetIRCDataThread exiting...\n");
	return;
}

/* return codes: 0=OK(found it), 1=TRY AGAIN, 2=FAILED(bad data) */
int CQnetGateway::get_yrcall_rptr_from_cache(const std::string &call, std::string &rptr, std::string &gate, std::string &addr, char RoU)
{
	switch (RoU) {
		case 'U':
			ii->cache.findUserData(call, rptr, gate, addr);
			if (rptr.empty()) {
				printf("Could not find last heard repeater for user '%s'\n", call.c_str());
				return 1;
			}
			break;
		case 'R':
			rptr.assign(call);
			ii->cache.findRptrData(call, gate, addr);
			break;
		default:
			fprintf(stderr, "ERROR: Invalid Rou of '%c'\n", RoU);
			return 2;
	}
	std::string temp;

	if (rptr.at(7) == 'G') {
		fprintf(stderr, "ERROR: Invalid module %c\n", rptr.at(7));
		return 2;
	}

	if (addr.empty()) {
		printf("Couldn't find IP address for %s\n", ('R' == RoU) ? "repeater" : "user");
		return 1;
	}
	return 0;
}

bool CQnetGateway::get_yrcall_rptr(const std::string &call, std::string &rptr, std::string &gate, std::string &addr, char RoU)
// returns false if unsuccessful
{
	if (0 == get_yrcall_rptr_from_cache(call, rptr, gate, addr, RoU))
		return true;

	/* at this point, the data is not in cache */
	if (ii->getConnectionState() > 5) {
		// we can try a find
		if (RoU == 'U') {
			printf("User [%s] not in local cache, try again\n", call.c_str());
			/*** YRCALL=KJ4NHFBL ***/
			if (((call.at(6) == 'A') || (call.at(6) == 'B') || (call.at(6) == 'C')) && (call.at(7) == 'L'))
				printf("If this was a gateway link request, that is ok\n");
			if (!ii->findUser(call))
				printf("findUser(%s): Network error\n", call.c_str());
		} else if (RoU == 'R') {
			printf("Repeater [%s] not found\n", call.c_str());
		}
	}
	return false;
}

bool CQnetGateway::Flag_is_ok(unsigned char flag)
{
	//      normal          break          emr          emr+break
	return 0x00U==flag || 0x08U==flag || 0x20U==flag || 0x28U==flag;
}

void CQnetGateway::ProcessTimeouts()
{
	for (int i=0; i<3; i++) {
		time_t t_now;
		/* echotest recording timed out? */
		if (recd[i].last_time != 0) {
			time(&t_now);
			if ((t_now - recd[i].last_time) > echotest_rec_timeout) {
				printf("Inactivity on echotest recording mod %d, removing stream id=%04x\n", i, ntohs(recd[i].streamid));

				recd[i].streamid = 0;
				recd[i].last_time = 0;
				close(recd[i].fd);
				recd[i].fd = -1;
				// printf("Closed echotest audio file:[%s]\n", recd[i].file);

				/* START: echotest thread setup */
				try {
					std::async(std::launch::async, &CQnetGateway::PlayFileThread, this, std::ref(recd[i]));
				} catch (const std::exception &e) {
					printf("Failed to start echotest thread. Exception: %s\n", e.what());
					// when the echotest thread runs, it deletes the file,
					// Because the echotest thread did NOT start, we delete the file here
					unlink(recd[i].file);
				}
				/* END: echotest thread setup */
			}
		}

		/* voicemail recording timed out? */
		if (vm[i].last_time != 0) {
			time(&t_now);
			if ((t_now - vm[i].last_time) > voicemail_rec_timeout) {
				printf("Inactivity on voicemail recording mod %d, removing stream id=%04x\n", i, ntohs(vm[i].streamid));

				vm[i].streamid = 0;
				vm[i].last_time = 0;
				close(vm[i].fd);
				vm[i].fd = -1;
				// printf("Closed voicemail audio file:[%s]\n", vm[i].file);
			}
		}

		// any stream going to local repeater timed out?
		if (toRptr[i].last_time != 0) {
			time(&t_now);
			//   The stream can be from a cross-band, or from a remote system,
			//   so we could use either FROM_LOCAL_RPTR_TIMEOUT or FROM_REMOTE_G2_TIMEOUT
			//   but FROM_REMOTE_G2_TIMEOUT makes more sense, probably is a bigger number
			if ((t_now - toRptr[i].last_time) > from_remote_g2_timeout) {
				printf("Inactivity to local rptr mod index %d, removing stream id %04x\n", i, ntohs(toRptr[i].streamid));

				// Send end_of_audio to local repeater.
				// Let the repeater re-initialize
				end_of_audio.counter = G2_COUNTER_OUT++;
				if (i == 0)
					end_of_audio.vpkt.snd_term_id = 0x03;
				else if (i == 1)
					end_of_audio.vpkt.snd_term_id = 0x01;
				else
					end_of_audio.vpkt.snd_term_id = 0x02;
				end_of_audio.vpkt.streamid = toRptr[i].streamid;
				end_of_audio.vpkt.ctrl = toRptr[i].sequence | 0x40;

				for (int j=0; j<2; j++)
					sendto(srv_sock, end_of_audio.pkt_id, 29, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());


				toRptr[i].streamid = 0;
				toRptr[i].adr.Clear();
				toRptr[i].last_time = 0;
			}
		}

		/* any stream coming from local repeater timed out ? */
		if (band_txt[i].last_time != 0) {
			time(&t_now);
			if ((t_now - band_txt[i].last_time) > from_local_rptr_timeout) {
				/* This local stream never went to a remote system, so trace the timeout */
				if (to_remote_g2[i].addr.AddressIsZero())
					printf("Inactivity from local rptr band %d, removing stream id %04x\n", i, ntohs(band_txt[i].streamID));

				band_txt[i].streamID = 0;
				band_txt[i].flags[0] = band_txt[i].flags[1] = band_txt[i].flags[2] = 0x0;
				band_txt[i].lh_mycall[0] = '\0';
				band_txt[i].lh_sfx[0] = '\0';
				band_txt[i].lh_yrcall[0] = '\0';
				band_txt[i].lh_rpt1[0] = '\0';
				band_txt[i].lh_rpt2[0] = '\0';

				band_txt[i].last_time = 0;

				band_txt[i].txt[0] = '\0';
				band_txt[i].txt_cnt = 0;

				band_txt[i].dest_rptr.clear();

				band_txt[i].num_dv_frames = 0;
				band_txt[i].num_dv_silent_frames = 0;
				band_txt[i].num_bit_errors = 0;
			}
		}

		/* any stream from local repeater to a remote gateway timed out ? */
		if (! to_remote_g2[i].addr.AddressIsZero()) {
			time(&t_now);
			if ((t_now - to_remote_g2[i].last_time) > from_local_rptr_timeout) {
				printf("Inactivity from local rptr mod %d, removing stream id %04x\n", i, ntohs(to_remote_g2[i].streamid));

				to_remote_g2[i].addr.Clear();
				to_remote_g2[i].streamid = 0;
				to_remote_g2[i].last_time = 0;
			}
		}
	}
}

bool CQnetGateway::ProcessG2Msg(const unsigned char *data, const int mod, std::string &smrtgrp)
{
	static unsigned int part[3] = { 0 };
	static char txt[3][21];
	if ((data[0] != 0x55u) || (data[1] != 0x2du) || (data[2] != 0x16u)) {
		const unsigned char c[3] = {
			static_cast<unsigned char>(data[0] ^ 0x70u),
			static_cast<unsigned char>(data[1] ^ 0x4fu),
			static_cast<unsigned char>(data[2] ^ 0x93u)
		};	// unscramble
		if (part[mod]) {
			// we are in a message
			if (part[mod] % 2) {
				// this is the second part of the 2-frame pair
				memcpy(txt[mod]+(5u*(part[mod]/2u)+2u), c, 3);
				if (++part[mod] > 7) {
					// we've got everything!
					part[mod] = 0;	// now we can start over
					if (0 == strncmp(txt[mod], "VIA SMARTGP ", 12))
						smrtgrp.assign(txt[mod]+12);
					if (smrtgrp.size() < 8) {
						// something bad happened
						smrtgrp.empty();
						return false;
					}
					return true;
				}
			} else {	// we'll get here when part[mod] = 2, 4 or 6
				unsigned int sequence = part[mod]++ / 2;	// this is the sequency we are expecting, 1, 2 or 3
				if ((sequence | 0x40u) == c[0]) {
					memcpy(txt[mod]+(5u*sequence), c+1, 2);	// got it, copy the 2 remainin chars
				} else {
					part[mod] = 0;	// unexpected
				}
			}
		} else if (0x40u == c[0]) {
			// start a new message
			memcpy(txt[mod], c+1, 2);
			memset(txt[mod]+2, 0, 19);
			part[mod] = 1;
		}
	} else {
		part[mod] = 0;	// messages will never be spread across a superframe
	}
	return false;
}

// new_group is true if we are processing the first voice packet of a 2-voice packet pair. The high order nibble of the first byte of
// this first packet specifed the type of slow data that is being sent.
// the to_print is an integer that counts down how many 2-voice-frame pairs remain to be processed.
// ABC_grp means that we are processing a 20-character message.
// C_seen means that we are processing the last 2-voice-frame packet on a 20 character message.
void CQnetGateway::ProcessSlowData(unsigned char *data, unsigned short sid)
{
	/* extract 20-byte RADIO ID */
	if ((data[0] != 0x55) || (data[1] != 0x2d) || (data[2] != 0x16)) {

		// first, unscramble
		unsigned char c1 = data[0] ^ 0x70u;
		unsigned char c2 = data[1] ^ 0x4fu;
		unsigned char c3 = data[2] ^ 0x93u;

		for (int i=0; i<3; i++) {
			if (band_txt[i].streamID == sid) {
				if (new_group[i]) {
					header_type = c1 & 0xf0;

					//                 header                   squelch
					if ((header_type == 0x50) || (header_type == 0xc0)) {
						new_group[i] = false;
						to_print[i] = 0;
						ABC_grp[i] = false;
					}
					else if (header_type == 0x30) { /* GPS or GPS id or APRS */
						new_group[i] = false;
						to_print[i] = c1 & 0x0f;
						ABC_grp[i] = false;
						if (to_print[i] > 5)
							to_print[i] = 5;
						else if (to_print[i] < 1)
							to_print[i] = 1;

						if ((to_print[i] > 1) && (to_print[i] <= 5)) {
							/* something went wrong? all bets are off */
							if (band_txt[i].temp_line_cnt > 200) {
								printf("Reached the limit in the OLD gps mode\n");
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							}

							/* fresh GPS string, re-initialize */
							if ((to_print[i] == 5) && (c2 == '$')) {
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							}

							/* do not copy CR, NL */
							if ((c2 != '\r') && (c2 != '\n')) {
								band_txt[i].temp_line[band_txt[i].temp_line_cnt] = c2;
								band_txt[i].temp_line_cnt++;
							}
							if ((c3 != '\r') && (c3 != '\n')) {
								band_txt[i].temp_line[band_txt[i].temp_line_cnt] = c3;
								band_txt[i].temp_line_cnt++;
							}

							if ((c2 == '\r') || (c3 == '\r')) {
								if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
									memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
									band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
								} else if (band_txt[i].temp_line[0] != '$') {
									memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
									band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
									if (bool_send_aprs && !band_txt[i].is_gps_sent)
										gps_send(i);
								}
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							} else if ((c2 == '\n') || (c3 == '\n')) {
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							}
							to_print[i] -= 2;
						} else {
							/* something went wrong? all bets are off */
							if (band_txt[i].temp_line_cnt > 200) {
								printf("Reached the limit in the OLD gps mode\n");
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							}

							/* do not copy CR, NL */
							if ((c2 != '\r') && (c2 != '\n')) {
								band_txt[i].temp_line[band_txt[i].temp_line_cnt] = c2;
								band_txt[i].temp_line_cnt++;
							}

							if (c2 == '\r') {
								if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
									memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
									band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
								} else if (band_txt[i].temp_line[0] != '$') {
									memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
									band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
									if (bool_send_aprs && !band_txt[i].is_gps_sent)
										gps_send(i);
								}
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							} else if (c2 == '\n') {
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							}
							to_print[i] --;
						}
					}
					else if (header_type == 0x40) { /* ABC text */
						new_group[i] = false;
						to_print[i] = 3;
						ABC_grp[i] = true;
						C_seen[i] = ((c1 & 0x0f) == 0x03) ? true : false;

						band_txt[i].txt[band_txt[i].txt_cnt] = c2;
						band_txt[i].txt_cnt++;

						band_txt[i].txt[band_txt[i].txt_cnt] = c3;
						band_txt[i].txt_cnt++;

						/* We should NOT see any more text,
						   if we already processed text,
						   so blank out the codes. */
						if (band_txt[i].sent_key_on_msg) {
							data[0] = 0x70;
							data[1] = 0x4f;
							data[2] = 0x93;
						}

						if (band_txt[i].txt_cnt >= 20) {
							band_txt[i].txt[band_txt[i].txt_cnt] = '\0';
							band_txt[i].txt_cnt = 0;
						}
					}
					else {	// header type is not header, squelch, gps or message
						new_group[i] = false;
						to_print[i] = 0;
						ABC_grp[i] = false;
					}
				}
				else { // not a new_group, this is the second of a two-voice-frame pair
					if (! band_txt[i].sent_key_on_msg && vPacketCount > 100) {
						// 100 voice packets received and still no 20-char message!
						/*** if YRCALL is CQCQCQ, set dest_rptr ***/
						band_txt[i].txt[0] = '\0';
						if (memcmp(band_txt[i].lh_yrcall, "CQCQCQ", 6) == 0) {
							set_dest_rptr(i, band_txt[i].dest_rptr);
						}
						// we have the 20-character message, send it to the server...
						ii->sendHeardWithTXMsg(band_txt[i].lh_mycall, band_txt[i].lh_sfx, band_txt[i].lh_yrcall, band_txt[i].lh_rpt1, band_txt[i].lh_rpt2, band_txt[i].flags[0], band_txt[i].flags[1], band_txt[i].flags[2], band_txt[i].dest_rptr, band_txt[i].txt);
						band_txt[i].sent_key_on_msg = true;
					}
					if (to_print[i] == 3) {
						if (ABC_grp[i]) {
							band_txt[i].txt[band_txt[i].txt_cnt] = c1;
							band_txt[i].txt_cnt++;

							band_txt[i].txt[band_txt[i].txt_cnt] = c2;
							band_txt[i].txt_cnt++;

							band_txt[i].txt[band_txt[i].txt_cnt] = c3;
							band_txt[i].txt_cnt++;

							/* We should NOT see any more text,
							   if we already processed text,
							   so blank out the codes. */
							if (band_txt[i].sent_key_on_msg) {
								data[0] = 0x70;
								data[1] = 0x4f;
								data[2] = 0x93;
							}

							if ((band_txt[i].txt_cnt >= 20) || C_seen[i]) {
								band_txt[i].txt[band_txt[i].txt_cnt] = '\0';
								if ( ! band_txt[i].sent_key_on_msg) {
									/*** if YRCALL is CQCQCQ, set dest_rptr ***/
									if (memcmp(band_txt[i].lh_yrcall, "CQCQCQ", 6) == 0) {
										set_dest_rptr(i, band_txt[i].dest_rptr);
									}
									// we have the 20-character message, send it to the server...
									ii->sendHeardWithTXMsg(band_txt[i].lh_mycall, band_txt[i].lh_sfx, band_txt[i].lh_yrcall, band_txt[i].lh_rpt1, band_txt[i].lh_rpt2, band_txt[i].flags[0], band_txt[i].flags[1], band_txt[i].flags[2], band_txt[i].dest_rptr, band_txt[i].txt);
									band_txt[i].sent_key_on_msg = true;
								}
								band_txt[i].txt_cnt = 0;
							}
							if (C_seen[i])
								C_seen[i] = false;
						} else {
							/* something went wrong? all bets are off */
							if (band_txt[i].temp_line_cnt > 200) {
								printf("Reached the limit in the OLD gps mode\n");
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							}

							/* do not copy carrige return or newline */
							if ((c1 != '\r') && (c1 != '\n')) {
								band_txt[i].temp_line[band_txt[i].temp_line_cnt++] = c1;
							}
							if ((c2 != '\r') && (c2 != '\n')) {
								band_txt[i].temp_line[band_txt[i].temp_line_cnt++] = c2;
							}
							if ((c3 != '\r') && (c3 != '\n')) {
								band_txt[i].temp_line[band_txt[i].temp_line_cnt++] = c3;
							}

							if ( (c1 == '\r') || (c2 == '\r') || (c3 == '\r') ) {
								if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
									memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
									band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
								} else if (band_txt[i].temp_line[0] != '$') {
									memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
									band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
									if (bool_send_aprs && !band_txt[i].is_gps_sent)
										gps_send(i);
								}
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							}
							else if ((c1 == '\n') || (c2 == '\n') ||(c3 == '\n')) {
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
							}
						}
					} else if (to_print[i] == 2) {
						/* something went wrong? all bets are off */
						if (band_txt[i].temp_line_cnt > 200) {
							printf("Reached the limit in the OLD gps mode\n");
							band_txt[i].temp_line[0] = '\0';
							band_txt[i].temp_line_cnt = 0;
						}

						/* do not copy CR, NL */
						if ((c1 != '\r') && (c1 != '\n')) {
							band_txt[i].temp_line[band_txt[i].temp_line_cnt++] = c1;
						}
						if ((c2 != '\r') && (c2 != '\n')) {
							band_txt[i].temp_line[band_txt[i].temp_line_cnt++] = c2;
						}

						if ((c1 == '\r') || (c2 == '\r')) {
							if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
								memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
								band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
							} else if (band_txt[i].temp_line[0] != '$') {
								memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
								band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
								if (bool_send_aprs && !band_txt[i].is_gps_sent)
									gps_send(i);
							}
							band_txt[i].temp_line[0] = '\0';
							band_txt[i].temp_line_cnt = 0;
						} else if ((c1 == '\n') || (c2  == '\n')) {
							band_txt[i].temp_line[0] = '\0';
							band_txt[i].temp_line_cnt = 0;
						}
					} else if (to_print[i] == 1) {
						/* something went wrong? all bets are off */
						if (band_txt[i].temp_line_cnt > 200) {
							printf("Reached the limit in the OLD gps mode\n");
							band_txt[i].temp_line[0] = '\0';
							band_txt[i].temp_line_cnt = 0;
						}

						/* do not copy CR, NL */
						if ((c1 != '\r') && (c1 != '\n')) {
							band_txt[i].temp_line[band_txt[i].temp_line_cnt++] = c1;
						}

						if (c1 == '\r') {
							if (memcmp(band_txt[i].temp_line, "$GPRMC", 6) == 0) {
								memcpy(band_txt[i].gprmc, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
								band_txt[i].gprmc[band_txt[i].temp_line_cnt] = '\0';
							} else if (band_txt[i].temp_line[0] != '$') {
								memcpy(band_txt[i].gpid, band_txt[i].temp_line, band_txt[i].temp_line_cnt);
								band_txt[i].gpid[band_txt[i].temp_line_cnt] = '\0';
								if (bool_send_aprs && !band_txt[i].is_gps_sent)
									gps_send(i);
							}
							band_txt[i].temp_line[0] = '\0';
							band_txt[i].temp_line_cnt = 0;
						} else if (c1 == '\n') {
							band_txt[i].temp_line[0] = '\0';
							band_txt[i].temp_line_cnt = 0;
						}
					}
					new_group[i] = true;
					to_print[i] = 0;
					ABC_grp[i] = false;
				}
				break;
			}
		}
	}
}

/* run the main loop for QnetGateway */
void CQnetGateway::Process()
{
	static unsigned char nextctrl[3] = { 0, 0, 0 };
	static std::string superframe[3];
	// dtmf stuff
	int dtmf_buf_count[3] = {0, 0, 0};
	char dtmf_buf[3][MAX_DTMF_BUF + 1] = { {""}, {""}, {""} };
	int dtmf_last_frame[3] = { 0, 0, 0 };
	unsigned int dtmf_counter[3] = { 0, 0, 0 };

	int max_nfds = 0;
	if (g2_sock > max_nfds)
		max_nfds = g2_sock;
	if (srv_sock > max_nfds)
		max_nfds = srv_sock;
	printf("g2=%d, srv=%d, MAX+1=%d\n", g2_sock, srv_sock, max_nfds + 1);

	std::future<void> aprs_future, irc_data_future;
	if (bool_send_aprs) {	// start the beacon thread
		try {
			aprs_future = std::async(std::launch::async, &CQnetGateway::APRSBeaconThread, this);
		} catch (const std::exception &e) {
			printf("Failed to start the APRSBeaconThread. Exception: %s\n", e.what());
		}
		if (aprs_future.valid())
			printf("APRS beacon thread started\n");
	}

	try {	// start the IRC read thread
		irc_data_future = std::async(std::launch::async, &CQnetGateway::GetIRCDataThread, this);
	} catch (const std::exception &e) {
		printf("Failed to start GetIRCDataThread. Exception: %s\n", e.what());
		keep_running = false;
	}
	if (keep_running)
		printf("get_irc_data thread started\n");

	ii->kickWatchdog(VERSION);

	do {
		// send INIT to Icom Stack
		unsigned char buf[500];
		memset(buf, 0, 10);
		memcpy(buf, "INIT", 4);
		buf[6] = 0x73U;
		// we can use the module a band_addr for INIT
		sendto(srv_sock, buf, 10, 0, toRptr[avalidmodule].addr.GetCPointer(), toRptr[avalidmodule].addr.GetSize());
		printf("Waiting for ICOM controller...\n");

		// get the acknowledgement from the ICOM Stack
		while (keep_running) {
			socklen_t fromlength = sizeof(struct sockaddr_in);
			int recvlen = recvfrom(srv_sock, buf, 500, 0, (struct sockaddr *)&fromRptr, &fromlength);
			if (10==recvlen && 0==memcmp(buf, "INIT", 4) && 0x72U==buf[6] && 0x0U==buf[7]) {
				OLD_REPLY_SEQ = 256U * buf[4] + buf[5];
				NEW_REPLY_SEQ = OLD_REPLY_SEQ + 1;
				G2_COUNTER_OUT = NEW_REPLY_SEQ;
				unsigned int ui = G2_COUNTER_OUT;
				printf("SYNC: old=%u, new=%u out=%u\n", OLD_REPLY_SEQ, NEW_REPLY_SEQ, ui);
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		printf("Detected ICOM controller!\n");
	} while (false);

	while (keep_running) {
		ProcessTimeouts();

		// wait 20 ms max
		fd_set fdset;
		FD_ZERO(&fdset);
		FD_SET(g2_sock, &fdset);
		FD_SET(srv_sock, &fdset);
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 20000; // 20 ms
		(void)select(max_nfds + 1, &fdset, 0, 0, &tv);

		// process packets coming from remote G2
		if (FD_ISSET(g2_sock, &fdset)) {
			static std::string lhcallsign[3], lhsfx[3];
			SDSVT g2buf;
			socklen_t fromlen = sizeof(struct sockaddr_storage);
			int g2buflen = recvfrom(g2_sock, g2buf.title, 56, 0, fromDst4.GetPointer(), &fromlen);

			// save incoming port for mobile systems
			const std::string addr(fromDst4.GetAddress());
			if (portmap.end() == portmap.find(addr)) {
				printf("New g2 contact at %s on port %u\n", addr.c_str(), fromDst4.GetPort());
				portmap[addr] = fromDst4.GetPort();
			} else {
				if (fromDst4.GetPort() != portmap[addr]) {
					printf("New g2 port from %s is now %u, it was %u\n", addr.c_str(), fromDst4.GetPort(), portmap[addr]);
					portmap[addr] = fromDst4.GetPort();
				}
			}

			if ( (g2buflen==56 || g2buflen==27) && 0==memcmp(g2buf.title, "DSVT", 4) && (g2buf.config==0x10 || g2buf.config==0x20) && g2buf.id==0x20) {
				if (g2buflen == 56) {

					// Find out the local repeater module IP/port to send the data to
					int i = g2buf.hdr.rpt1[7] - 'A';

					/* valid repeater module? */
					if (i>=0 && i<3) {
						// toRptr[i] is active if a remote system is talking to it or
						// toRptr[i] is receiving data from a cross-band
						if (0==toRptr[i].last_time && 0==band_txt[i].last_time && (Flag_is_ok(g2buf.hdr.flag[0]) || 0x01U==g2buf.hdr.flag[0] || 0x40U==g2buf.hdr.flag[0])) {
							if (bool_qso_details)
								printf("id=%04x G2 start, ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s IP=[%s]:%u\n", ntohs(g2buf.streamid), g2buf.hdr.urcall, g2buf.hdr.rpt1, g2buf.hdr.rpt2, g2buf.hdr.mycall, g2buf.hdr.sfx, fromDst4.GetAddress(), fromDst4.GetPort());

							lhcallsign[i].assign((const char *)g2buf.hdr.mycall, 8);
							if (showLastHeard && memcmp(g2buf.hdr.sfx, "RPTR", 4) && std::regex_match(lhcallsign[i].c_str(), preg)) {
								lhsfx[i].assign((const char *)g2buf.hdr.sfx, 4);
								std::string  reflector((const char *)g2buf.hdr.urcall, 8);
								if (0 == reflector.compare("CQCQCQ  "))
									set_dest_rptr('A'+i, reflector);
								else if (0 == reflector.compare(OWNER))
									reflector.assign("CSRoute");
								qnDB.UpdateLH(lhcallsign[i].c_str(), lhsfx[i].c_str(), 'A'+i, reflector.c_str());
							}

							memcpy(rptrbuf.pkt_id, "DSTR", 4);
							rptrbuf.counter = htons(G2_COUNTER_OUT++);	// bump the counter
							rptrbuf.flag[0] = 0x73;
							rptrbuf.flag[1] = 0x12;
							rptrbuf.flag[2] = 0x00;
							rptrbuf.remaining = 0x30;
							rptrbuf.vpkt.icm_id = 0x20;
							//memcpy(&rptrbuf.vpkt.dst_rptr_id, g2buf.flagb, 47);
							rptrbuf.vpkt.dst_rptr_id = g2buf.flagb[0];
							rptrbuf.vpkt.snd_rptr_id = g2buf.flagb[1];
							rptrbuf.vpkt.snd_term_id = g2buf.flagb[2];
							rptrbuf.vpkt.streamid    = g2buf.streamid;
							rptrbuf.vpkt.ctrl        = g2buf.ctrl;
							memcpy(rptrbuf.vpkt.hdr.flag, g2buf.hdr.flag,   3);
							memcpy(rptrbuf.vpkt.hdr.r1,   g2buf.hdr.rpt2,   8);
							memcpy(rptrbuf.vpkt.hdr.r2,   g2buf.hdr.rpt1,   8);
							memcpy(rptrbuf.vpkt.hdr.ur,   g2buf.hdr.urcall, 8);
							memcpy(rptrbuf.vpkt.hdr.my,   g2buf.hdr.mycall, 8);
							memcpy(rptrbuf.vpkt.hdr.nm,   g2buf.hdr.sfx,    4);
							memcpy(rptrbuf.vpkt.hdr.pfcs, g2buf.hdr.pfcs,   2);
							sendto(srv_sock, rptrbuf.pkt_id, 58, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());

							/* save the header */
							memcpy(toRptr[i].saved_hdr, rptrbuf.pkt_id, 58);
							toRptr[i].saved_adr = fromDst4;

							/* This is the active streamid */
							toRptr[i].streamid = g2buf.streamid;
							toRptr[i].adr = fromDst4;

							/* time it, in case stream times out */
							time(&toRptr[i].last_time);

							toRptr[i].sequence = rptrbuf.vpkt.ctrl;
							nextctrl[i] = 0U;	// ctrl of the next voice packet (used for healing code)
						}
					}
				} else {	// g2buflen == 27

					/* find out which repeater module to send the data to */
					int i;
					for (i=0; i<3; i++) {
						/* streamid match ? */
						if (toRptr[i].streamid==g2buf.streamid && toRptr[i].adr==fromDst4) {
							memcpy(rptrbuf.pkt_id, "DSTR", 4);
							//rptrbuf.counter = htons(G2_COUNTER_OUT++);
							rptrbuf.flag[0] = 0x73;
							rptrbuf.flag[1] = 0x12;
							rptrbuf.flag[2] = 0x00;
							rptrbuf.remaining= 0x13;
							rptrbuf.vpkt.icm_id = 0x20;
							memcpy(&rptrbuf.vpkt.dst_rptr_id, g2buf.flagb, 18);

							//healing
							if (bool_log_debug) {
								const unsigned int ctrl = g2buf.ctrl & 0x3FU;
								if (g2buf.vasd.text[0]==0x55U && g2buf.vasd.text[1]==0x2DU && g2buf.vasd.text[2]==0x16U) {
									if (superframe[i].size() > 65U) {
										printf("Frame[%c]: %s\n", 'A'+i, superframe[i].c_str());
										superframe[i].clear();
									}
									const char *ch = "#abcdefghijklmnopqrstuvwxyz";
									superframe[i].append(1, (ctrl<27U) ? ch[ctrl] : '%' );
								} else {
									const char *ch = "!ABCDEFGHIJKLMNOPQRSTUVWXYZ";
									superframe[i].append(1, (ctrl<27U) ? ch[ctrl] : '*' );
								}
							}

							int diff = int(0x1FU & g2buf.ctrl) - int(nextctrl[i]);
							if (diff) {
								if (diff < 0)
									diff += 21;
								if (diff < 6) {	// fill up to 5 missing voice frames
									if (bool_log_debug)
										fprintf(stderr, "Warning: inserting %d missing voice frame(s)\n", diff - 1);
									SDSTR dstr;
									memcpy(dstr.pkt_id, rptrbuf.pkt_id, 16U);	// everything but the ctrl and voice data
									const unsigned char quite[9] = { 0x9EU, 0x8DU, 0x32U, 0x88U, 0x26U, 0x1AU, 0x3FU, 0x61U, 0xE8U };
									memcpy(g2buf.vasd.voice, quite, 9);
									while (diff-- > 0) {
										dstr.counter = htons(G2_COUNTER_OUT++);
										dstr.vpkt.ctrl = nextctrl[i]++;
										nextctrl[i] %= 21U;
										if (dstr.vpkt.ctrl) {
											const unsigned char text[3] = { 0x70U, 0x4FU, 0x93U };
											memcpy(dstr.vpkt.vasd.text, text, 3U);
										} else {
											const unsigned char sync[3] = { 0x55U, 0x2DU, 0x16U };
											memcpy(dstr.vpkt.vasd.voice, sync, 3U);
										}
										sendto(srv_sock, rptrbuf.pkt_id, 29, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());
									}
								} else {
									if (bool_log_debug)
										printf("missing %d packets from voice stream on module %c, resetting\n", diff, 'A'+i);
									nextctrl[i] = g2buf.ctrl;
								}
							}

							if ((nextctrl[i] == (0x1FU & g2buf.ctrl)) || (0x40U & g2buf.ctrl)) {
								// no matter what, we will send this on if it is the closing frame
								if (0x40U & g2buf.ctrl) {
									g2buf.ctrl = (nextctrl[i] | 0x40U);
								} else {
									g2buf.ctrl = nextctrl[i];
									nextctrl[i] = (nextctrl[i] + 1U) % 21U;
								}
								rptrbuf.counter = htons(G2_COUNTER_OUT++);
								sendto(srv_sock, rptrbuf.pkt_id, 29, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());
								if (showLastHeard) {
									std::string smartgroup;
									if (ProcessG2Msg(g2buf.vasd.text, i, smartgroup)) {
										qnDB.UpdateLH(lhcallsign[i].c_str(), lhsfx[i].c_str(), 'A'+i, smartgroup.c_str());
									}
								}
							} else {
								if (bool_log_debug)
									fprintf(stderr, "Warning: Ignoring packet because its ctrl=0x%02xU and nextctrl=0x%02xU\n", g2buf.ctrl, nextctrl[i]);
							}


							/* timeit */
							time(&toRptr[i].last_time);

							toRptr[i].sequence = rptrbuf.vpkt.ctrl;

							/* End of stream ? */
							if (g2buf.ctrl & 0x40) {
								/* clear the saved header */
								memset(toRptr[i].saved_hdr, 0, sizeof(toRptr[i].saved_hdr));
								toRptr[i].saved_adr.Clear();

								toRptr[i].last_time = 0;
								toRptr[i].streamid = 0;
								toRptr[i].adr.Clear();
								if (bool_log_debug && superframe[i].size()) {
									printf("Final[%c]: %s\n", 'A'+i, superframe[i].c_str());
									superframe[i].clear();
								}
								if (bool_qso_details)
									printf("id=%04x END\n", ntohs(g2buf.streamid));
							}
							break;
						}
					}

					/* no match ? */
					if ((i == 3) && bool_regen_header) {
						/* check if this a continuation of audio that timed out */

						if (g2buf.ctrl & 0x40)
							;  /* we do not care about end-of-QSO */
						else {
							/* for which repeater this stream has timed out ?  */
							for (i = 0; i < 3; i++) {
								/* match saved stream ? */
								if (0==memcmp(toRptr[i].saved_hdr + 14, &g2buf.streamid, 2) && toRptr[i].saved_adr==fromDst4) {
									/* repeater module is inactive ?  */
									if (toRptr[i].last_time==0 && band_txt[i].last_time==0) {
										printf("Re-generating header for streamID=%04x\n", g2buf.streamid);

										toRptr[i].saved_hdr[4] = (unsigned char)((G2_COUNTER_OUT>>8) & 0xFFU);
										toRptr[i].saved_hdr[5] = (unsigned char)((G2_COUNTER_OUT++) & 0xFFU);

										/* re-generate/send the header */
										sendto(srv_sock, toRptr[i].saved_hdr, 58, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());

										/* send this audio packet to repeater */
										memcpy(rptrbuf.pkt_id, "DSTR", 4);
										rptrbuf.counter = htons(G2_COUNTER_OUT++);
										rptrbuf.flag[0] = 0x73;
										rptrbuf.flag[1] = 0x12;
										rptrbuf.flag[2] = 0x00;
										rptrbuf.remaining = 0x13;
										rptrbuf.vpkt.icm_id = 0x20;
										memcpy(&rptrbuf.vpkt.dst_rptr_id, g2buf.flagb, 18);

										sendto(srv_sock, rptrbuf.pkt_id, 29, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());

										/* make sure that any more audio arriving will be accepted */
										toRptr[i].streamid = g2buf.streamid;
										toRptr[i].adr = fromDst4;

										/* time it, in case stream times out */
										time(&toRptr[i].last_time);

										toRptr[i].sequence = rptrbuf.vpkt.ctrl;

									}
									break;
								}
							}
						}
					}
				}
			}
			FD_CLR (g2_sock,&fdset);
		}

		// process packets coming from local repeater modules
		if (FD_ISSET(srv_sock, &fdset)) {
			std::string user;

			char tempfile[FILENAME_MAX + 1];

			SDSVT g2buf;

			socklen_t fromlen = sizeof(struct sockaddr_storage);
			int recvlen = recvfrom(srv_sock, rptrbuf.pkt_id, 58,  0, fromRptr.GetPointer(), &fromlen);

			if (0 == memcmp(rptrbuf.pkt_id, "DSTR", 4)) {
				/////////////////////////////////////////////////////////////////////
				// some ICOM handshaking...
				if (10==recvlen && 0x72==rptrbuf.flag[0]) {	// ACK from rptr
					NEW_REPLY_SEQ = ntohs(rptrbuf.counter);
					if (NEW_REPLY_SEQ == OLD_REPLY_SEQ) {
						G2_COUNTER_OUT = NEW_REPLY_SEQ;
						OLD_REPLY_SEQ = NEW_REPLY_SEQ - 1;
					} else
						OLD_REPLY_SEQ = NEW_REPLY_SEQ;
				} else if (0x73U==rptrbuf.flag[0] && (0x21U==rptrbuf.flag[1] || 0x11U==rptrbuf.flag[1] || 0x0U==rptrbuf.flag[1])) {
					rptrbuf.flag[0] = 0x72U;
					memset(rptrbuf.flag+1, 0x0U, 3);
					sendto(srv_sock, rptrbuf.pkt_id, 10, 0, toRptr[avalidmodule].addr.GetCPointer(), toRptr[avalidmodule].addr.GetSize());
				// end of ICOM handshaking
				/////////////////////////////////////////////////////////////////////
				} else if ( (recvlen==58 || recvlen==29 || recvlen==32) && rptrbuf.flag[0]==0x73 && rptrbuf.flag[1]==0x12 && rptrbuf.flag[2]==0x0 && rptrbuf.vpkt.icm_id==0x20 && (rptrbuf.remaining==0x30 || rptrbuf.remaining==0x13 || rptrbuf.remaining==0x16) ) {
					do {	// acknowledge packet to ICOM
						SDSTR reply;
						memcpy(reply.pkt_id, "DSTR", 4);
						reply.counter = rptrbuf.counter;
						reply.flag[0] = 0x72U;
						memset(reply.flag+1, 0, 3);
						sendto(srv_sock, reply.pkt_id, 10, 0, toRptr[avalidmodule].addr.GetCPointer(), toRptr[avalidmodule].addr.GetSize());
					} while(false);

					if (recvlen == 58) {
						vPacketCount = 0U;
						if (bool_qso_details)
							printf("id=%04x cntr=%04x start RPTR flag0=%02x ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s ip=[%s]:%u\n", ntohs(rptrbuf.vpkt.streamid), ntohs(rptrbuf.counter), rptrbuf.vpkt.hdr.flag[0], rptrbuf.vpkt.hdr.ur, rptrbuf.vpkt.hdr.r1, rptrbuf.vpkt.hdr.r2, rptrbuf.vpkt.hdr.my, rptrbuf.vpkt.hdr.nm, fromRptr.GetAddress(), fromRptr.GetPort());

						if (0==memcmp(rptrbuf.vpkt.hdr.r1, OWNER.c_str(), 7) &&	Flag_is_ok(rptrbuf.vpkt.hdr.flag[0])) {

							int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

							if (i>=0  && i<3) {
								if (bool_dtmf_debug)
									printf("resetting dtmf[%d] (got a header)\n", i);
								dtmf_last_frame[i] = 0;
								dtmf_counter[i] = 0;
								memset(dtmf_buf[i], 0, sizeof(dtmf_buf[i]));
								dtmf_buf_count[i] = 0;

								/* Initialize the LAST HEARD data for the band */

								band_txt[i].streamID = rptrbuf.vpkt.streamid;

								memcpy(band_txt[i].flags, rptrbuf.vpkt.hdr.flag, 3);

								memcpy(band_txt[i].lh_mycall, rptrbuf.vpkt.hdr.my, 8);
								band_txt[i].lh_mycall[8] = '\0';

								memcpy(band_txt[i].lh_sfx, rptrbuf.vpkt.hdr.nm, 4);
								band_txt[i].lh_sfx[4] = '\0';

								memcpy(band_txt[i].lh_yrcall, rptrbuf.vpkt.hdr.ur, 8);
								band_txt[i].lh_yrcall[8] = '\0';

								memcpy(band_txt[i].lh_rpt1, rptrbuf.vpkt.hdr.r1, 8);
								band_txt[i].lh_rpt1[8] = '\0';

								memcpy(band_txt[i].lh_rpt2, rptrbuf.vpkt.hdr.r2, 8);
								band_txt[i].lh_rpt2[8] = '\0';

								time(&band_txt[i].last_time);

								band_txt[i].txt[0] = '\0';
								band_txt[i].txt_cnt = 0;
								band_txt[i].sent_key_on_msg = false;

								band_txt[i].dest_rptr.clear();

								/* try to process GPS mode: GPRMC and ID */
								band_txt[i].temp_line[0] = '\0';
								band_txt[i].temp_line_cnt = 0;
								band_txt[i].gprmc[0] = '\0';
								band_txt[i].gpid[0] = '\0';
								band_txt[i].is_gps_sent = false;
								// band_txt[i].gps_last_time = 0; DO NOT reset it

								new_group[i] = true;
								to_print[i] = 0;
								ABC_grp[i] = false;

								band_txt[i].num_dv_frames = 0;
								band_txt[i].num_dv_silent_frames = 0;
								band_txt[i].num_bit_errors = 0;

								/* select the band for aprs processing, and lock on the stream ID */
								if (bool_send_aprs)
									aprs->SelectBand(i, ntohs(rptrbuf.vpkt.streamid));
							}
						}

						/* Is MYCALL valid ? */
						user.assign((const char *)rptrbuf.vpkt.hdr.my, 8);

						bool mycall_valid = std::regex_match(user, preg);

						if (mycall_valid)
							sendto(srv_sock, rptrbuf.pkt_id, recvlen, 0, plug.GetCPointer(), plug.GetSize());
						else
							printf("MYCALL [%s] failed IRC expression validation\n", user.c_str());

						if ( mycall_valid &&
								memcmp(rptrbuf.vpkt.hdr.ur, "XLX", 3) &&	// not a reflector
								memcmp(rptrbuf.vpkt.hdr.ur, "XRF", 3) &&
								memcmp(rptrbuf.vpkt.hdr.ur, "REF", 3) &&
								memcmp(rptrbuf.vpkt.hdr.ur, "DCS", 3) &&
								rptrbuf.vpkt.hdr.ur[0]!=' ' && 				// must have something
								memcmp(rptrbuf.vpkt.hdr.ur, "CQCQCQ", 6) )	// urcall is NOT CQCQCQ
						{
							if ( rptrbuf.vpkt.hdr.ur[0]=='/' &&										// repeater routing!
									0==memcmp(rptrbuf.vpkt.hdr.r1, OWNER.c_str(), 7) &&				// rpt1 this repeater
									(rptrbuf.vpkt.hdr.r1[7]>='A' && rptrbuf.vpkt.hdr.r1[7]<='C') &&	// with a valid module
									0==memcmp(rptrbuf.vpkt.hdr.r2, OWNER.c_str(), 7) && 			// rpt2 is this repeater
									rptrbuf.vpkt.hdr.r2[7]=='G' &&									// local Gateway
									Flag_is_ok(rptrbuf.vpkt.hdr.flag[0]) )
							{
								if (memcmp(rptrbuf.vpkt.hdr.ur+1, OWNER.c_str(), 6)) {	// the value after the slash is NOT this repeater
									int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

									if (i>=0 && i<3) {
										/* one radio user on a repeater module at a time */
										if (to_remote_g2[i].addr.AddressIsZero()) {
											/* YRCALL=/repeater + mod */
											/* YRCALL=/KJ4NHFB */

											user.assign((const char *)rptrbuf.vpkt.hdr.ur+1, 6);
											user.push_back(' ');
											user.push_back(rptrbuf.vpkt.hdr.ur[7]);
											if (user.at(7) == ' ')
												user[7] = 'A';

											std::string rptr, gate, addr;
											bool result = get_yrcall_rptr(user, rptr, gate, addr, 'R');
											if (result) { /* it is a repeater */
												/* set the destination */
												to_remote_g2[i].streamid = rptrbuf.vpkt.streamid;

												// if the address is in the portmap, we'll use that saved port instead of the default port
												auto pos = portmap.find(addr);
												auto port = (pos==portmap.end()) ? g2_external.port : pos->second;
												to_remote_g2[i].addr.Initialize(AF_INET, port, addr.c_str());

												memcpy(g2buf.title, "DSVT", 4);
												g2buf.config = 0x10;
												g2buf.flaga[0] = g2buf.flaga[1] = g2buf.flaga[2] = 0x00;
												g2buf.id =  rptrbuf.vpkt.icm_id;
												g2buf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
												g2buf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
												g2buf.flagb[2] = rptrbuf.vpkt.snd_term_id;
												g2buf.streamid = rptrbuf.vpkt.streamid;
												g2buf.ctrl = rptrbuf.vpkt.ctrl;
												memcpy(g2buf.hdr.flag, rptrbuf.vpkt.hdr.flag, 3);
												/* set rpt1 */
												memset(g2buf.hdr.rpt1, ' ', 8);
												memcpy(g2buf.hdr.rpt1, rptr.c_str(), rptr.size());
												/* set rpt2 */
												memset(g2buf.hdr.rpt2, ' ', 8);
												memcpy(g2buf.hdr.rpt2, gate.c_str(), gate.size());
												/* set yrcall, can NOT let it be slash and repeater + module */
												memcpy(g2buf.hdr.urcall, "CQCQCQ  ", 8);
												memcpy(g2buf.hdr.mycall, rptrbuf.vpkt.hdr.my, 8);
												memcpy(g2buf.hdr.sfx, rptrbuf.vpkt.hdr.nm, 4);

												/* set PFCS */
												calcPFCS(g2buf.title, 56);

												// The remote repeater has been set, lets fill in the dest_rptr
												// so that later we can send that to the LIVE web site
												band_txt[i].dest_rptr.assign((const char *)g2buf.hdr.rpt1, 8);

												// send to remote gateway
												for (int j=0; j<5; j++)
													sendto(g2_sock, g2buf.title, 56, 0, to_remote_g2[i].addr.GetCPointer(), to_remote_g2[i].addr.GetSize());

												printf("id=%04x Routing to IP=[%s]:%u ur=%.8s r1=%.8s r2=%.8s my=%.8s/%.4s\n", ntohs(g2buf.streamid), to_remote_g2[i].addr.GetAddress(), to_remote_g2[i].addr.GetPort(), g2buf.hdr.urcall, g2buf.hdr.rpt1, g2buf.hdr.rpt2, g2buf.hdr.mycall, g2buf.hdr.sfx);

												time(&(to_remote_g2[i].last_time));
											}
										}
									}
								}
							}
							else if (memcmp(rptrbuf.vpkt.hdr.ur, OWNER.c_str(), 7) &&				// urcall is not this repeater
									0==memcmp(rptrbuf.vpkt.hdr.r1, OWNER.c_str(), 7) &&				// rpt1 is this repeater
									(rptrbuf.vpkt.hdr.r1[7]>='A'&& rptrbuf.vpkt.hdr.r1[7]<='C') &&	// mod is A,B,C
									0==memcmp(rptrbuf.vpkt.hdr.r2, OWNER.c_str(), 7) &&				// rpt2 is this repeater
									rptrbuf.vpkt.hdr.r2[7]=='G' &&									// local Gateway
									Flag_is_ok(rptrbuf.vpkt.hdr.flag[0])) {


								user.assign((const char *)rptrbuf.vpkt.hdr.ur, 8);
								std::string rptr, gate, addr;
								bool result = get_yrcall_rptr(user, rptr, gate, addr, 'U');
								if (result) {
									/* destination is a remote system */
									if (gate.compare(0, 7, OWNER, 0, 7)) {
										int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

										if (i>=0 && i<3) {
											/* one radio user on a repeater module at a time */
											if (to_remote_g2[i].addr.AddressIsZero()) {
												/* set the destination */
												to_remote_g2[i].streamid = rptrbuf.vpkt.streamid;

												// if the address is in the portmap, we'll use that port instead of the default
												auto pos = portmap.find(addr);
												auto port = (pos==portmap.end())? g2_external.port : pos->second;
												to_remote_g2[i].addr.Initialize(AF_INET, port, addr.c_str());

												memcpy(g2buf.title, "DSVT", 4);
												g2buf.config = 0x10;
												g2buf.flaga[0] = g2buf.flaga[1] = g2buf.flaga[2] = 0x00;
												g2buf.id = rptrbuf.vpkt.icm_id;
												g2buf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
												g2buf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
												g2buf.flagb[2] = rptrbuf.vpkt.snd_term_id;
												g2buf.streamid = rptrbuf.vpkt.streamid;
												g2buf.ctrl = rptrbuf.vpkt.ctrl;
												memcpy(g2buf.hdr.flag, rptrbuf.vpkt.hdr.flag, 3);
												/* set rpt1 */
												memset(g2buf.hdr.rpt1, ' ', 8);
												memcpy(g2buf.hdr.rpt1, rptr.c_str(), rptr.size());
												/* set rpt2 */
												memset(g2buf.hdr.rpt2, ' ', 8);
												memcpy(g2buf.hdr.rpt2, gate.c_str(), gate.size());
												/* set PFCS */
												memcpy(g2buf.hdr.urcall, rptrbuf.vpkt.hdr.ur, 8);
												memcpy(g2buf.hdr.mycall, rptrbuf.vpkt.hdr.my, 8);
												memcpy(g2buf.hdr.sfx, rptrbuf.vpkt.hdr.nm, 4);
												calcPFCS(g2buf.title, 56);


												// The remote repeater has been set, lets fill in the dest_rptr
												// so that later we can send that to the LIVE web site
												band_txt[i].dest_rptr.assign((const char *)g2buf.hdr.rpt1, 8);

												/* send to remote gateway */
												for (int j=0; j<5; j++)
													sendto(g2_sock, g2buf.title, 56, 0, to_remote_g2[i].addr.GetCPointer(), to_remote_g2[i].addr.GetSize());

												printf("Routing to IP=[%s]:%u id=%04x my=%.8s/%.4s ur=%.8s rpt1=%.8s rpt2=%.8s\n", to_remote_g2[i].addr.GetAddress(), to_remote_g2[i].addr.GetPort(), ntohs(g2buf.streamid), g2buf.hdr.mycall, g2buf.hdr.sfx, g2buf.hdr.urcall, g2buf.hdr.rpt1, g2buf.hdr.rpt2);

												time(&(to_remote_g2[i].last_time));
											}
										}
									}
									else
									{
										int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

										if (i>=0 && i<3) {
											/* the user we are trying to contact is on our gateway */
											/* make sure they are on a different module */
											if (rptr.at(7) != rptrbuf.vpkt.hdr.r1[7]) {
												/*
												   The remote repeater has been set, lets fill in the dest_rptr
												   so that later we can send that to the LIVE web site
												*/
												band_txt[i].dest_rptr.assign((const char *)rptrbuf.vpkt.hdr.r2, 7);
												band_txt[i].dest_rptr.push_back(rptr.at(7));

												i = rptr.at(7) - 'A';

												/* valid destination repeater module? */
												if (i>=0 && i<3) {
													/*
													   toRptr[i] :    receiving from a remote system or cross-band
													   band_txt[i] :  local RF is talking.
													*/
													if ((toRptr[i].last_time == 0) && (band_txt[i].last_time == 0)) {
														printf("CALLmode cross-banding from mod %c to %c\n",  rptrbuf.vpkt.hdr.r1[7], rptr.at(7));

														rptrbuf.vpkt.hdr.r2[7] = rptr.at(7);
														rptrbuf.vpkt.hdr.r1[7] = 'G';
														calcPFCS(rptrbuf.pkt_id, 58);

														sendto(srv_sock, rptrbuf.pkt_id, 58, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());

														/* This is the active streamid */
														toRptr[i].streamid = rptrbuf.vpkt.streamid;
														toRptr[i].adr = fromRptr;

														/* time it, in case stream times out */
														time(&toRptr[i].last_time);

														/* bump the G2 counter */
														G2_COUNTER_OUT++;

														toRptr[i].sequence = rptrbuf.vpkt.ctrl;
													}
												}
											}
											else
												printf("icom rule: no routing from %8.8s to %s\n", rptrbuf.vpkt.hdr.r1, rptr.c_str());
										}
									}
								}
								else
								{
									if ('L' != rptrbuf.vpkt.hdr.ur[7]) // as long as this doesn't look like a linking command
										playNotInCache = true; // we need to wait until user's transmission is over
								}
							}
						}
						else if (0 == memcmp(rptrbuf.vpkt.hdr.ur, "      C0", 8)) {
							int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

							if (i>=0 && i<3) {
								/* voicemail file is closed */
								if ((vm[i].fd == -1) && (vm[i].file[0] != '\0')) {
									unlink(vm[i].file);
									printf("removed voicemail file: %s\n", vm[i].file);
									vm[i].file[0] = '\0';
								} else
									printf("No voicemail to clear or still recording\n");
							}
						}
						else if (0 == memcmp(rptrbuf.vpkt.hdr.ur, "      R0", 8)) {
							int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

							if (i>=0 && i<3) {
								/* voicemail file is closed */
								if ((vm[i].fd == -1) && (vm[i].file[0] != '\0')) {
									snprintf(vm[i].message, 21, "VOICEMAIL ON MOD %c  ", 'A'+i);
									try {
										std::async(std::launch::async, &CQnetGateway::PlayFileThread, this, std::ref(vm[i]));
									} catch (const std::exception &e) {
										printf("Failed to start voicemail playback. Exception: %s\n", e.what());
									}
								} else
									printf("No voicemail to recall or still recording\n");
							}
						}
						else if (0 == memcmp(rptrbuf.vpkt.hdr.ur, "      S0", 8)) {
							int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

							if (i>=0 && i<3) {
								if (vm[i].fd >= 0)
									printf("Already recording for voicemail on mod %d\n", i);
								else {
									memset(tempfile, '\0', sizeof(tempfile));
									snprintf(tempfile, FILENAME_MAX, "%s/%c_%s", echotest_dir.c_str(), rptrbuf.vpkt.hdr. r1[7], "voicemail.dat");

									vm[i].fd = open(tempfile, O_CREAT | O_WRONLY | O_TRUNC | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
									if (vm[i].fd < 0)
										printf("Failed to create file %s for voicemail\n", tempfile);
									else {
										strcpy(vm[i].file, tempfile);
										printf("Recording mod %c for voicemail into file:[%s]\n", rptrbuf.vpkt.hdr.r1[7], vm[i].file);

										time(&vm[i].last_time);
										vm[i].streamid = rptrbuf.vpkt.streamid;

										memcpy(recbuf.title, "DSVT", 4);
										recbuf.config = 0x10;
										recbuf.flaga[0] = recbuf.flaga[1] = recbuf.flaga[2] = 0;
										recbuf.id =  rptrbuf.vpkt.icm_id;
										recbuf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
										recbuf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
										recbuf.flagb[2] = rptrbuf.vpkt.snd_term_id;
										memcpy(&recbuf.streamid, &rptrbuf.vpkt.streamid, 44);
										memset(recbuf.hdr.rpt1, ' ', 8);
										memcpy(recbuf.hdr.rpt1, OWNER.c_str(), OWNER.size());
										recbuf.hdr.rpt1[7] = rptrbuf.vpkt.hdr.r1[7];
										memset(recbuf.hdr.rpt2, ' ', 8);
										memcpy(recbuf.hdr.rpt2,  OWNER.c_str(), OWNER.size());
										recbuf.hdr.rpt2[7] = 'G';
										memcpy(recbuf.hdr.urcall, "CQCQCQ  ", 8);

										calcPFCS(recbuf.title, 56);

										memcpy(vm[i].header.title, recbuf.title, 56);
									}
								}
							}
						}
						else if (0 == memcmp(rptrbuf.vpkt.hdr.ur, "       E", 8)) {
							int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

							if (i>=0 && i<3) {
								if (recd[i].fd >= 0)
									printf("Already recording for echotest on mod %d\n", i);
								else {
									memset(tempfile, '\0', sizeof(tempfile));
									snprintf(tempfile, FILENAME_MAX, "%s/%c_%s", echotest_dir.c_str(), rptrbuf.vpkt.hdr.r1[7], "echotest.dat");

									recd[i].fd = open(tempfile, O_CREAT | O_WRONLY | O_EXCL | O_TRUNC | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
									if (recd[i].fd < 0)
										printf("Failed to create file %s for echotest\n", tempfile);
									else {
										strcpy(recd[i].file, tempfile);
										printf("Recording mod %c for echotest into file:[%s]\n", rptrbuf.vpkt.hdr.r1[7], recd[i].file);
										snprintf(recd[i].message, 21, "ECHO ON MODULE %c    ", 'A' + i);
										time(&recd[i].last_time);
										recd[i].streamid = rptrbuf.vpkt.streamid;

										memcpy(recbuf.title, "DSVT", 4);
										recbuf.config = 0x10;
										recbuf.id =  rptrbuf.vpkt.icm_id;
										recbuf.flaga[0] = recbuf.flaga[1] = recbuf.flaga[2] = 0;
										recbuf.flagb[0] = rptrbuf.vpkt.dst_rptr_id;
										recbuf.flagb[1] = rptrbuf.vpkt.snd_rptr_id;
										recbuf.flagb[2] = rptrbuf.vpkt.snd_term_id;
										memcpy(&recbuf.streamid, &rptrbuf.vpkt.streamid, 44);
										memset(recbuf.hdr.rpt1, ' ', 8);
										memcpy(recbuf.hdr.rpt1, OWNER.c_str(), OWNER.length());
										recbuf.hdr.rpt1[7] = rptrbuf.vpkt.hdr.r1[7];
										memset(recbuf.hdr.rpt2, ' ', 8);
										memcpy(recbuf.hdr.rpt2,  OWNER.c_str(), OWNER.length());
										recbuf.hdr.rpt2[7] = 'G';
										memcpy(recbuf.hdr.urcall, "CQCQCQ  ", 8);

										calcPFCS(recbuf.title, 56);

										memcpy(recd[i].header.title, recbuf.title, 56);
									}
								}
							}
						/* check for cross-banding */
						}
						else if ( 0==memcmp(rptrbuf.vpkt.hdr.ur, "CQCQCQ", 6) &&		// yrcall is CQCQCQ
									0==memcmp(rptrbuf.vpkt.hdr.r2, OWNER.c_str(), 7) &&	// rpt1 is this repeater
									0==memcmp(rptrbuf.vpkt.hdr.r1, OWNER.c_str(), 7) &&	// rpt2 is this repeater
								(rptrbuf.vpkt.hdr.r1[7]>='A' && rptrbuf.vpkt.hdr.r1[7]<='C') &&	// mod of rpt1 is A,B,C
								(rptrbuf.vpkt.hdr.r2[7]>='A' && rptrbuf.vpkt.hdr.r2[7]<='C') &&	// !!! usually G on rpt2, but we see A,B,C with
								rptrbuf.vpkt.hdr.r2[7]!=rptrbuf.vpkt.hdr.r1[7] ) {				// cross-banding? make sure NOT the same
							int i = rptrbuf.vpkt.hdr.r1[7] - 'A';

							if (i>=0 && i<3) {
								// The remote repeater has been set, lets fill in the dest_rptr
								// so that later we can send that to the LIVE web site
								band_txt[i].dest_rptr.assign((const char *)rptrbuf.vpkt.hdr.r2, 8);
							}

							i = rptrbuf.vpkt.hdr.r2[7] - 'A';

							// valid destination repeater module?
							if (i>=0 && i<3) {
								// toRptr[i] :    receiving from a remote system or cross-band
								// band_txt[i] :  local RF is talking.
								if ((toRptr[i].last_time == 0) && (band_txt[i].last_time == 0)) {
									printf("ZONEmode cross-banding from mod %c to %c\n",  rptrbuf.vpkt.hdr.r1[7], rptrbuf.vpkt.hdr.r2[7]);

									rptrbuf.vpkt.hdr.r1[7] = 'G';
									calcPFCS(rptrbuf.pkt_id, 58);

									sendto(srv_sock, rptrbuf.pkt_id, 58, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());

									/* This is the active streamid */
									toRptr[i].streamid = rptrbuf.vpkt.streamid;
									toRptr[i].adr = fromRptr;

									/* time it, in case stream times out */
									time(&toRptr[i].last_time);

									/* bump the G2 counter */
									G2_COUNTER_OUT++;

									toRptr[i].sequence = rptrbuf.vpkt.ctrl;
								}
							}
						}
					}
					else
					{	// recvlen is 29 or 32
						for (int i=0; i<3; i++) {
							if (band_txt[i].streamID == rptrbuf.vpkt.streamid) {
								time(&band_txt[i].last_time);

								if (rptrbuf.vpkt.ctrl & 0x40) {	// end of voice data
									if (dtmf_buf_count[i] > 0) {
										dtmf_file = dtmf_dir;
										dtmf_file.push_back('/');
										dtmf_file.push_back('A'+i);
										dtmf_file += "_mod_DTMF_NOTIFY";
										if (bool_dtmf_debug)
											printf("Saving dtmfs=[%s] into file: [%s]\n", dtmf_buf[i], dtmf_file.c_str());
										FILE *dtmf_fp = fopen(dtmf_file.c_str(), "w");
										if (dtmf_fp) {
											fprintf(dtmf_fp, "%s\n%s", dtmf_buf[i], band_txt[i].lh_mycall);
											fclose(dtmf_fp);
										} else
											printf("Failed to create dtmf file %s\n", dtmf_file.c_str());


										if (bool_dtmf_debug)
											printf("resetting dtmf[%d] (printed dtmf code %s from %s)\n", i, dtmf_buf[i], band_txt[i].lh_mycall);
										memset(dtmf_buf[i], 0, sizeof(dtmf_buf[i]));
										dtmf_buf_count[i] = 0;
										dtmf_counter[i] = 0;
										dtmf_last_frame[i] = 0;
									}
									if (! band_txt[i].sent_key_on_msg) {
										band_txt[i].txt[0] = '\0';
										if (memcmp(band_txt[i].lh_yrcall, "CQCQCQ", 6) == 0) {
											set_dest_rptr(i, band_txt[i].dest_rptr);
										}
										// we have the 20-character message, send it to the server...
										ii->sendHeardWithTXMsg(band_txt[i].lh_mycall, band_txt[i].lh_sfx, (strstr(band_txt[i].lh_yrcall,"REF") == NULL)?band_txt[i].lh_yrcall:"CQCQCQ  ", band_txt[i].lh_rpt1, band_txt[i].lh_rpt2, band_txt[i].flags[0], band_txt[i].flags[1], band_txt[i].flags[2], band_txt[i].dest_rptr, band_txt[i].txt);
										band_txt[i].sent_key_on_msg = true;
									}
									// send the "key off" message, this will end up in the openquad.net Last Heard webpage.
									ii->sendHeardWithTXStats(band_txt[i].lh_mycall, band_txt[i].lh_sfx, band_txt[i].lh_yrcall, band_txt[i].lh_rpt1, band_txt[i].lh_rpt2, band_txt[i].flags[0], band_txt[i].flags[1], band_txt[i].flags[2], band_txt[i].num_dv_frames, band_txt[i].num_dv_silent_frames, band_txt[i].num_bit_errors);

									if (playNotInCache) {
										// Not in cache, please try again!
										FILE *fp = fopen(qnvoicefile.c_str(), "w");
										if (fp) {
											fprintf(fp, "%c_notincache.dat_NOT_IN_CACHE\n", band_txt[i].lh_rpt1[7]);
											fclose(fp);
										}
										playNotInCache = false;
									}

									band_txt[i].streamID = 0;
									band_txt[i].flags[0] = band_txt[i].flags[1] = band_txt[i].flags[2] = 0;
									band_txt[i].lh_mycall[0] = '\0';
									band_txt[i].lh_sfx[0] = '\0';
									band_txt[i].lh_yrcall[0] = '\0';
									band_txt[i].lh_rpt1[0] = '\0';
									band_txt[i].lh_rpt2[0] = '\0';

									band_txt[i].last_time = 0;

									band_txt[i].txt[0] = '\0';
									band_txt[i].txt_cnt = 0;

									band_txt[i].dest_rptr.clear();

									band_txt[i].num_dv_frames = 0;
									band_txt[i].num_dv_silent_frames = 0;
									band_txt[i].num_bit_errors = 0;
								}
								else
								{	// not the end of the voice stream
									int ber_data[3];
									int ber_errs = dstar_decode.Decode(rptrbuf.vpkt.vasd.voice, ber_data);
									if (ber_data[0] == 0xf85)
										band_txt[i].num_dv_silent_frames++;
									band_txt[i].num_bit_errors += ber_errs;
									band_txt[i].num_dv_frames++;

									if ((ber_data[0] & 0x0ffc) == 0xfc0) {
										dtmf_digit = (ber_data[0] & 0x03) | ((ber_data[2] & 0x60) >> 3);
										if (dtmf_counter[i] > 0) {
											if (dtmf_last_frame[i] != dtmf_digit)
												dtmf_counter[i] = 0;
										}
										dtmf_last_frame[i] = dtmf_digit;
										dtmf_counter[i]++;

										if ((dtmf_counter[i] == 5) && (dtmf_digit >= 0) && (dtmf_digit <= 15)) {
											if (dtmf_buf_count[i] < MAX_DTMF_BUF) {
												const char *dtmf_chars = "147*2580369#ABCD";
												dtmf_buf[i][ dtmf_buf_count[i] ] = dtmf_chars[dtmf_digit];
												dtmf_buf_count[i]++;
											}
										}
										const unsigned char silence[9] = { 0x9E, 0x8D, 0x32, 0x88, 0x26, 0x1A, 0x3F, 0x61, 0xE8 };
										if (recvlen == 29)
											memcpy(rptrbuf.vpkt.vasd.voice, silence, 9);
										else
											memcpy(rptrbuf.vpkt.vasd1.voice, silence, 9);
									} else
										dtmf_counter[i] = 0;
								}
								break;
							}
						}
						vPacketCount++;
						if (recvlen == 29)	// process the slow data from every voice packet
							ProcessSlowData(rptrbuf.vpkt.vasd.text,  rptrbuf.vpkt.streamid);
						else
							ProcessSlowData(rptrbuf.vpkt.vasd1.text, rptrbuf.vpkt.streamid);

						/* send data to qnlink */
						sendto(srv_sock, rptrbuf.pkt_id, recvlen, 0, plug.GetCPointer(), plug.GetSize());

						/* aprs processing */
						if (bool_send_aprs)
							//                             streamID               seq                audio+text
							aprs->ProcessText(ntohs(rptrbuf.vpkt.streamid), rptrbuf.vpkt.ctrl, rptrbuf.vpkt.vasd.voice);

						for (int i=0; i<3; i++) {
							/* find out if data must go to the remote G2 */
							if (to_remote_g2[i].streamid == rptrbuf.vpkt.streamid) {
								memcpy(g2buf.title, "DSVT", 4);
								g2buf.config = 0x20;
								g2buf.flaga[0] = g2buf.flaga[1] = g2buf.flaga[2] = 0;
								memcpy(&g2buf.id, &rptrbuf.vpkt.icm_id, 7);
								if (recvlen == 29)
									memcpy(g2buf.vasd.voice, rptrbuf.vpkt.vasd.voice, 12);
								else
									memcpy(g2buf.vasd.voice, rptrbuf.vpkt.vasd1.voice, 12);

								const std::string addr(to_remote_g2[i].addr.GetAddress());
								auto family = to_remote_g2[i].addr.GetFamily();
								// if the address is in the portmap, we'll use that port instead of the default
								auto pos = portmap.find(addr);
								auto port = (pos==portmap.end()) ? g2_external.port : pos->second;
								to_remote_g2[i].addr.Initialize(family, port, addr.c_str());
								sendto(g2_sock, g2buf.title, 27, 0, to_remote_g2[i].addr.GetCPointer(), to_remote_g2[i].addr.GetSize());

								time(&(to_remote_g2[i].last_time));

								/* Is this the end-of-stream */
								if (rptrbuf.vpkt.ctrl & 0x40) {
									to_remote_g2[i].addr.Clear();
									to_remote_g2[i].streamid = 0;
									to_remote_g2[i].last_time = 0;
								}
								break;
							}
							else if (recd[i].fd>=0 && recd[i].streamid==rptrbuf.vpkt.streamid) {	// Is the data to be recorded for echotest
								time(&recd[i].last_time);

								if (recvlen == 29)
									(void)write(recd[i].fd, rptrbuf.vpkt.vasd.voice, 9);
								else
									(void)write(recd[i].fd, rptrbuf.vpkt.vasd1.voice, 9);

								if ((rptrbuf.vpkt.ctrl & 0x40) != 0) {
									recd[i].streamid = 0;
									recd[i].last_time = 0;
									close(recd[i].fd);
									recd[i].fd = -1;
									// printf("Closed echotest audio file:[%s]\n", recd[i].file);

									/* we are in echotest mode, so play it back */
									try {
										std::async(std::launch::async, &CQnetGateway::PlayFileThread, this, std::ref(recd[i]));
									} catch (const std::exception &e) {
										printf("failed to start PlayFileThread. Exception: %s\n", e.what());
										//   When the echotest thread runs, it deletes the file,
										//   Because the echotest thread did NOT start, we delete the file here
										unlink(recd[i].file);
									}
								}
								break;
							}
							else if ((vm[i].fd >= 0) && (vm[i].streamid==rptrbuf.vpkt.streamid)) {	// Is the data to be recorded for voicemail
								time(&vm[i].last_time);

								if (recvlen == 29)
									(void)write(vm[i].fd, rptrbuf.vpkt.vasd.voice, 9);
								else
									(void)write(vm[i].fd, rptrbuf.vpkt.vasd1.voice, 9);

								if ((rptrbuf.vpkt.ctrl & 0x40) != 0) {
									vm[i].streamid = 0;
									vm[i].last_time = 0;
									close(vm[i].fd);
									vm[i].fd = -1;
									// printf("Closed voicemail audio file:[%s]\n", vm[i].file);
								}
								break;
							}
							else if ((toRptr[i].streamid==rptrbuf.vpkt.streamid) && (toRptr[i].adr == fromRptr)) {	// or maybe this is cross-banding data
								sendto(srv_sock, rptrbuf.pkt_id, 29, 0, toRptr[i].addr.GetCPointer(), toRptr[i].addr.GetSize());

								/* timeit */
								time(&toRptr[i].last_time);

								/* bump G2 counter */
								G2_COUNTER_OUT++;

								toRptr[i].sequence = rptrbuf.vpkt.ctrl;

								/* End of stream ? */
								if (rptrbuf.vpkt.ctrl & 0x40) {
									toRptr[i].last_time = 0;
									toRptr[i].streamid = 0;
									toRptr[i].adr.Clear();
								}
								break;
							}
						}

						if (bool_qso_details && rptrbuf.vpkt.ctrl&0x40)
							printf("id=%04x cntr=%04x END RPTR\n", ntohs(rptrbuf.vpkt.streamid), ntohs(rptrbuf.counter));
					}
				}
			}
			FD_CLR (srv_sock, &fdset);
		}
	}

	// thread clean-up
	if (bool_send_aprs) {
		if (aprs_future.valid())
			aprs_future.get();
	}
	irc_data_future.get();
	return;
}

void CQnetGateway::compute_aprs_hash()
{
	short hash = 0x73e2;
	char rptr_sign[CALL_SIZE + 1];

	strcpy(rptr_sign, OWNER.c_str());
	char *p = strchr(rptr_sign, ' ');
	if (!p) {
		printf("Failed to build repeater callsign for aprs hash\n");
		return;
	}
	*p = '\0';
	p = rptr_sign;
	short int len = strlen(rptr_sign);

	for (short int i=0; i < len; i+=2) {
		hash ^= (*p++) << 8;
		hash ^= (*p++);
	}
	printf("aprs hash code=[%d] for %s\n", hash, OWNER.c_str());
	rptr.aprs_hash = hash;

	return;
}

void CQnetGateway::APRSBeaconThread()
{
	char snd_buf[512];
	char rcv_buf[512];
	time_t tnow = 0;

	struct sigaction act;

	/*
	   Every 20 seconds, the remote APRS host sends a KEEPALIVE packet-comment
	   on the TCP/APRS port.
	   If we have not received any KEEPALIVE packet-comment after 5 minutes
	   we must assume that the remote APRS host is down or disappeared
	   or has dropped the connection. In these cases, we must re-connect.
	   There are 3 keepalive packets in one minute, or every 20 seconds.
	   In 5 minutes, we should have received a total of 15 keepalive packets.
	*/
	short THRESHOLD_COUNTDOWN = 15;

	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		printf("APRSBeaconThread: sigaction-TERM failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		printf("APRSBeaconThread: sigaction-INT failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGPIPE, &act, 0) != 0) {
		printf("APRSBeaconThread: sigaction-PIPE failed, error=%d\n", errno);
		return;
	}

	time_t last_keepalive_time;
	time(&last_keepalive_time);

	time_t last_beacon_time = 0;
	/* This thread is also saying to the APRS_HOST that we are ALIVE */
	while (keep_running) {
		if (aprs->GetSock() == -1) {
			aprs->Open(OWNER);
			if (aprs->GetSock() == -1)
				sleep(1);
			else
				THRESHOLD_COUNTDOWN = 15;
		}

		time(&tnow);
		if ((tnow - last_beacon_time) > (rptr.aprs_interval * 60)) {
			for (short int i=0; i<3; i++) {
				if (rptr.mod[i].desc[0] != '\0') {
					float tmp_lat = fabs(rptr.mod[i].latitude);
					float tmp_lon = fabs(rptr.mod[i].longitude);
					float lat = floor(tmp_lat);
					float lon = floor(tmp_lon);
					lat = (tmp_lat - lat) * 60.0F + lat  * 100.0F;
					lon = (tmp_lon - lon) * 60.0F + lon  * 100.0F;

					char lat_s[15], lon_s[15];
					if (lat >= 1000.0F)
						sprintf(lat_s, "%.2f", lat);
					else if (lat >= 100.0F)
						sprintf(lat_s, "0%.2f", lat);
					else if (lat >= 10.0F)
						sprintf(lat_s, "00%.2f", lat);
					else
						sprintf(lat_s, "000%.2f", lat);

					if (lon >= 10000.0F)
						sprintf(lon_s, "%.2f", lon);
					else if (lon >= 1000.0F)
						sprintf(lon_s, "0%.2f", lon);
					else if (lon >= 100.0F)
						sprintf(lon_s, "00%.2f", lon);
					else if (lon >= 10.0F)
						sprintf(lon_s, "000%.2f", lon);
					else
						sprintf(lon_s, "0000%.2f", lon);

					/* send to aprs */
					sprintf(snd_buf, "%s>APJI23,TCPIP*,qAC,%sS:!%s%cD%s%c&RNG%04u %s %s",
					        rptr.mod[i].call.c_str(),  rptr.mod[i].call.c_str(),
					        lat_s,  (rptr.mod[i].latitude < 0.0)  ? 'S' : 'N',
					        lon_s,  (rptr.mod[i].longitude < 0.0) ? 'W' : 'E',
					        (unsigned int)rptr.mod[i].range, rptr.mod[i].band.c_str(), rptr.mod[i].desc.c_str());

					// printf("APRS Beacon =[%s]\n", snd_buf);
					strcat(snd_buf, "\r\n");

					while (keep_running) {
						if (aprs->GetSock() == -1) {
							aprs->Open(OWNER);
							if (aprs->GetSock() == -1)
								sleep(1);
							else
								THRESHOLD_COUNTDOWN = 15;
						} else {
							int rc = aprs->WriteSock(snd_buf, strlen(snd_buf));
							if (rc < 0) {
								if ((errno == EPIPE) ||
								        (errno == ECONNRESET) ||
								        (errno == ETIMEDOUT) ||
								        (errno == ECONNABORTED) ||
								        (errno == ESHUTDOWN) ||
								        (errno == EHOSTUNREACH) ||
								        (errno == ENETRESET) ||
								        (errno == ENETDOWN) ||
								        (errno == ENETUNREACH) ||
								        (errno == EHOSTDOWN) ||
								        (errno == ENOTCONN)) {
									printf("send_aprs_beacon: APRS_HOST closed connection,error=%d\n",errno);
									close(aprs->GetSock());
									aprs->SetSock( -1 );
								} else if (errno == EWOULDBLOCK) {
									std::this_thread::sleep_for(std::chrono::milliseconds(100));
								} else {
									/* Cant do nothing about it */
									printf("send_aprs_beacon failed, error=%d\n", errno);
									break;
								}
							} else {
								// printf("APRS beacon sent\n");
								break;
							}
						}
						int rc = recv(aprs->GetSock(), rcv_buf, sizeof(rcv_buf), 0);
						if (rc > 0)
							THRESHOLD_COUNTDOWN = 15;
					}
				}
				int rc = recv(aprs->GetSock(), rcv_buf, sizeof(rcv_buf), 0);
				if (rc > 0)
					THRESHOLD_COUNTDOWN = 15;
			}
			time(&last_beacon_time);
		}
		/*
		   Are we still receiving from APRS host ?
		*/
		int rc = recv(aprs->GetSock(), rcv_buf, sizeof(rcv_buf), 0);
		if (rc < 0) {
			if ((errno == EPIPE) ||
			        (errno == ECONNRESET) ||
			        (errno == ETIMEDOUT) ||
			        (errno == ECONNABORTED) ||
			        (errno == ESHUTDOWN) ||
			        (errno == EHOSTUNREACH) ||
			        (errno == ENETRESET) ||
			        (errno == ENETDOWN) ||
			        (errno == ENETUNREACH) ||
			        (errno == EHOSTDOWN) ||
			        (errno == ENOTCONN)) {
				printf("send_aprs_beacon: recv error: APRS_HOST closed connection,error=%d\n",errno);
				close(aprs->GetSock());
				aprs->SetSock( -1 );
			}
		} else if (rc == 0) {
			printf("send_aprs_beacon: recv: APRS shutdown\n");
			close(aprs->GetSock());
			aprs->SetSock( -1 );
		} else
			THRESHOLD_COUNTDOWN = 15;

		std::this_thread::sleep_for(std::chrono::milliseconds(100));

		/* 20 seconds passed already ? */
		time(&tnow);
		if ((tnow - last_keepalive_time) > 20) {
			/* we should be receving keepalive packets ONLY if the connection is alive */
			if (aprs->GetSock() >= 0) {
				if (THRESHOLD_COUNTDOWN > 0)
					THRESHOLD_COUNTDOWN--;

				if (THRESHOLD_COUNTDOWN == 0) {
					printf("APRS host keepalive timeout\n");
					close(aprs->GetSock());
					aprs->SetSock( -1 );
				}
			}
			/* reset timer */
			time(&last_keepalive_time);
		}
	}
	printf("APRS beacon thread exiting...\n");
	return;
}

void CQnetGateway::PlayFileThread(SECHO &edata)
{
	SDSTR dstr;
	const unsigned char sdsilence[3] = { 0x16U, 0x29U, 0xF5U };
	const unsigned char sdsync[3] = { 0x55U, 0x2DU, 0x16U };

	struct sigaction act;
	act.sa_handler = sigCatch;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGTERM, &act, 0) != 0) {
		printf("sigaction-TERM failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGINT, &act, 0) != 0) {
		printf("sigaction-INT failed, error=%d\n", errno);
		return;
	}
	if (sigaction(SIGPIPE, &act, 0) != 0) {
		printf("sigaction-PIPE failed, error=%d\n", errno);
		return;
	}

	printf("File to playback:[%s]\n", edata.file);

	struct stat sbuf;
	if (stat(edata.file, &sbuf)) {
		fprintf(stderr, "Can't stat %s\n", edata.file);
		return;
	}

	if (sbuf.st_size % 9)
		printf("Warning %s file size is %ld (not a multiple of 9)!\n", edata.file, sbuf.st_size);
	int ambeblocks = (int)sbuf.st_size / 9;

	FILE *fp = fopen(edata.file, "rb");
	if (!fp) {
		fprintf(stderr, "Failed to open file %s\n", edata.file);
		return;
	}

	int mod = edata.header.hdr.rpt1[7] - 'A';
	if (mod<0 || mod>2) {
		fprintf(stderr, "unknown module suffix '%s'\n", edata.header.hdr.rpt1);
		return;
	}

	sleep(play_wait);

	// reformat the header and send it
	memcpy(dstr.pkt_id, "DSTR", 4);
	dstr.counter = htons(G2_COUNTER_OUT++);
	dstr.flag[0] = 0x73;
	dstr.flag[1] = 0x12;
	dstr.flag[2] = 0x00;
	dstr.remaining = 0x30;
	dstr.vpkt.icm_id = 0x20;
	dstr.vpkt.dst_rptr_id = edata.header.flagb[0];
	dstr.vpkt.snd_rptr_id = edata.header.flagb[1];
	dstr.vpkt.snd_term_id = edata.header.flagb[2];
	dstr.vpkt.streamid    = edata.header.streamid;
	dstr.vpkt.ctrl        = 0x80u;
	memcpy(dstr.vpkt.hdr.flag, edata.header.hdr.flag,   3);
	memcpy(dstr.vpkt.hdr.r1,   edata.header.hdr.rpt2,   8);
	memcpy(dstr.vpkt.hdr.r2,   edata.header.hdr.rpt1,   8);
	memcpy(dstr.vpkt.hdr.ur,   "CQCQCQ  ",              8);
	memcpy(dstr.vpkt.hdr.my,   edata.header.hdr.mycall, 8);
	memcpy(dstr.vpkt.hdr.nm,   edata.header.hdr.sfx,    4);
	calcPFCS(dstr.pkt_id, 58);

	sendto(srv_sock, dstr.pkt_id, 58, 0, toRptr[mod].addr.GetCPointer(), toRptr[mod].addr.GetSize());

	dstr.remaining = 0x13U;

	for (int i=0; i<ambeblocks; i++) {

		int nread = fread(dstr.vpkt.vasd.voice, 9, 1, fp);
		if (nread == 1) {
			dstr.counter = htons(G2_COUNTER_OUT++);
			dstr.vpkt.ctrl = (unsigned char)(i % 21);
			if (0x0U == dstr.vpkt.ctrl) {
				memcpy(dstr.vpkt.vasd.text, sdsync, 3);
			} else {
				switch (i) {
					case 1:
						dstr.vpkt.vasd.text[0] = '@' ^ 0x70;
						dstr.vpkt.vasd.text[1] = edata.message[0] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = edata.message[1] ^ 0x93;
						break;
					case 2:
						dstr.vpkt.vasd.text[0] = edata.message[2] ^ 0x70;
						dstr.vpkt.vasd.text[1] = edata.message[3] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = edata.message[4] ^ 0x93;
						break;
					case 3:
						dstr.vpkt.vasd.text[0] = 'A' ^ 0x70;
						dstr.vpkt.vasd.text[1] = edata.message[5] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = edata.message[6] ^ 0x93;
						break;
					case 4:
						dstr.vpkt.vasd.text[0] = edata.message[7] ^ 0x70;
						dstr.vpkt.vasd.text[1] = edata.message[8] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = edata.message[9] ^ 0x93;
						break;
					case 5:
						dstr.vpkt.vasd.text[0] = 'B' ^ 0x70;
						dstr.vpkt.vasd.text[1] = edata.message[10] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = edata.message[11] ^ 0x93;
						break;
					case 6:
						dstr.vpkt.vasd.text[0] = edata.message[12] ^ 0x70;
						dstr.vpkt.vasd.text[1] = edata.message[13] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = edata.message[14] ^ 0x93;
						break;
					case 7:
						dstr.vpkt.vasd.text[0] = 'C' ^ 0x70;
						dstr.vpkt.vasd.text[1] = edata.message[15] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = edata.message[16] ^ 0x93;
						break;
					case 8:
						dstr.vpkt.vasd.text[0] = edata.message[17] ^ 0x70;
						dstr.vpkt.vasd.text[1] = edata.message[18] ^ 0x4f;
						dstr.vpkt.vasd.text[2] = edata.message[19] ^ 0x93;
						break;
					default:
						memcpy(dstr.vpkt.vasd.text, sdsilence, 3);
						break;
				}
			}
			if (i+1 == ambeblocks)
				dstr.vpkt.ctrl |= 0x40U;

			sendto(srv_sock, dstr.pkt_id, 29, 0, toRptr[mod].addr.GetCPointer(), toRptr[mod].addr.GetSize());

			std::this_thread::sleep_for(std::chrono::milliseconds(play_delay));
		}
	}
	fclose(fp);
	printf("Finished playing\n");
	// if it's an echo file, delete it!
	if (strstr(edata.file, "echotest.dat")) {
		unlink(edata.file);
		edata.file[0] = edata.message[0] = '\0';
	}
	return;
}

void CQnetGateway::qrgs_and_maps()
{
	for (int i=0; i<3; i++) {
		std::string rptrcall = OWNER;
		rptrcall.resize(CALL_SIZE-1);
		rptrcall += i + 'A';
		if (rptr.mod[i].latitude || rptr.mod[i].longitude || rptr.mod[i].desc1.length() || rptr.mod[i].url.length())
			ii->rptrQTH(rptrcall, rptr.mod[i].latitude, rptr.mod[i].longitude, rptr.mod[i].desc1, rptr.mod[i].desc2, rptr.mod[i].url, rptr.mod[i].package_version);
		if (rptr.mod[i].frequency)
			ii->rptrQRG(rptrcall, rptr.mod[i].frequency, rptr.mod[i].offset, rptr.mod[i].range, rptr.mod[i].agl);
	}

	return;
}

bool CQnetGateway::Init(char *cfgfile)
{
	setvbuf(stdout, (char *)NULL, _IOLBF, 0);


	/* Used to validate MYCALL input */
	/* Used to validate MYCALL input */
	try {
		preg = std::regex("^(([1-9][A-Z])|([A-PR-Z][0-9])|([A-PR-Z][A-Z][0-9]))[0-9A-Z]*[A-Z][ ]*[ A-RT-Z]$", std::regex::extended);
	} catch (std::regex_error &e) {
		printf("Regular expression error: %s\n", e.what());
		return true;
	}

	std::signal(SIGTERM, sigCatch);
	std::signal(SIGINT,  sigCatch);
	std::signal(SIGHUP,  sigCatch);

	for (int i=0; i<3; i++) {
		band_txt[i].streamID = 0;
		memset(band_txt[i].flags, 0, 3);
		memset(band_txt[i].lh_mycall, 0, 9);
		memset(band_txt[i].lh_sfx, 0, 5);
		memset(band_txt[i].lh_yrcall, 0, 9);
		memset(band_txt[i].lh_rpt1, 0, 9);
		memset(band_txt[i].lh_rpt2, 0, 9);
		band_txt[i].last_time = 0;
		memset(band_txt[i].txt, 0, 64);   // Only 20 are used
		band_txt[i].txt_cnt = 0;
		band_txt[i].sent_key_on_msg = false;
		band_txt[i].dest_rptr.clear();
		memset(band_txt[i].temp_line, 0, 256);
		band_txt[i].temp_line_cnt = 0U;
		memset(band_txt[i].gprmc, 0, 256);
		memset(band_txt[i].gpid, 0, 256);
		band_txt[i].is_gps_sent = false;
		band_txt[i].gps_last_time = 0;
		band_txt[i].num_dv_frames = 0;
		band_txt[i].num_dv_silent_frames = 0;
		band_txt[i].num_bit_errors = 0;
	}

	/* process configuration file */
	printf("Reading Configuration file %s...\n", cfgfile);
	if ( read_config(cfgfile) ) {
		printf("Failed to process config file %s\n", cfgfile);
		return true;
	}

	std::string dbfilename(CFG_DIR);
	dbfilename.append("/");
	dbfilename.append(DASH_SQL_NAME);
	if (qnDB.Open(dbfilename.c_str()))
		return true;
	qnDB.ClearLH();

	playNotInCache = false;

	/* build the repeater callsigns for aprs */
	rptr.mod[0].call = OWNER;
	trim(rptr.mod[0].call);

	rptr.mod[1].call = rptr.mod[0].call;
	rptr.mod[2].call = rptr.mod[0].call;
	rptr.mod[0].call += "-A";
	rptr.mod[1].call += "-B";
	rptr.mod[2].call += "-C";
	rptr.mod[0].band = "23cm";
	rptr.mod[1].band = "70cm";
	rptr.mod[2].band = "2m";
	printf("Repeater callsigns: [%s] [%s] [%s]\n", rptr.mod[0].call.c_str(), rptr.mod[1].call.c_str(), rptr.mod[2].call.c_str());

	if (bool_send_aprs) {
		aprs = new CAPRS(&rptr);
		if (aprs)
			aprs->Init();
		else {
			printf("aprs class init failed!\nAPRS will be turned off");
			bool_send_aprs = false;
		}
	}
	compute_aprs_hash();

	ii = new CIRCDDB(ircddb.ip, ircddb.port, owner, irc_pass, VERSION);
	bool ok = ii->open();
	if (!ok) {
		printf("irc open failed\n");
		return true;
	}

	int rc = ii->getConnectionState();
	printf("Waiting for irc connection status of 2\n");
	int i = 0;
	while (rc < 2) {
		printf("irc status=%d\n", rc);
		if (rc < 2) {
			i++;
			sleep(5);
		} else
			break;

		if (!keep_running)
			break;

		if (i > 5) {
			printf("We can not wait any longer...\n");
			break;
		}
		rc = ii->getConnectionState();
	}

	/* udp port 40000 must open first */
	g2_sock = open_port(g2_external);
	if (0 > g2_sock) {
		printf("Can't open %s:%d\n", g2_external.ip.c_str(), g2_external.port);
		return true;
	}

	// Open G2 INTERNAL:
	// default non-icom 127.0.0.1:19000
	// default icom     172.16.0.20:20000
	srv_sock = open_port(g2_internal);
	if (0 > srv_sock) {
		printf("Can't open %s:%d\n", g2_internal.ip.c_str(), g2_internal.port);
		return true;
	}

	for (i = 0; i < 3; i++) {
		// recording for echotest on local repeater modules
		recd[i].last_time = 0;
		recd[i].streamid = 0;
		recd[i].fd = -1;
		memset(recd[i].file, 0, sizeof(recd[i].file));

		// recording for voicemail on local repeater modules
		vm[i].last_time = 0;
		vm[i].streamid = 0;
		vm[i].fd = -1;
		memset(vm[i].file, 0, sizeof(vm[i].file));

		snprintf(vm[i].file, FILENAME_MAX, "%s/%c_%s", echotest_dir.c_str(), 'A'+i, "voicemail.dat");

		if (access(vm[i].file, F_OK) != 0)
			memset(vm[i].file, 0, sizeof(vm[i].file));
		else
			printf("Loaded voicemail file: %s for mod %d\n", vm[i].file, i);

		// the repeater modules run on these ports
		//memset(&toRptr[i], 0, sizeof(toRptr[i]));

		memset(toRptr[i].saved_hdr, 0, sizeof(toRptr[i].saved_hdr));
		toRptr[i].saved_adr.Clear();

		toRptr[i].streamid = 0;
		toRptr[i].adr.Clear();

		toRptr[i].addr.Initialize(AF_INET, rptr.mod[i].portip.port, rptr.mod[i].portip.ip.c_str());

		toRptr[i].last_time = 0;
		toRptr[i].G2_COUNTER = 0;

		toRptr[i].sequence = 0x0;
	}

	/*
	   Initialize the end_of_audio that will be sent to the local repeater
	   when audio from remote G2 has timed out
	*/
	memcpy(end_of_audio.pkt_id, "DSTR", 4);
	end_of_audio.flag[0] = 0x73;
	end_of_audio.flag[1] = 0x12;
	end_of_audio.flag[2] = 0x00;
	end_of_audio.remaining = 0x13;
	end_of_audio.vpkt.icm_id = 0x20;
	end_of_audio.vpkt.dst_rptr_id = 0x00;
	end_of_audio.vpkt.snd_rptr_id = 0x01;
	memset(end_of_audio.vpkt.vasd.voice, '\0', 9);
	end_of_audio.vpkt.vasd.text[0] = 0x70;
	end_of_audio.vpkt.vasd.text[1] = 0x4f;
	end_of_audio.vpkt.vasd.text[2] = 0x93;

	/* to remote systems */
	for (i=0; i<3; i++) {
		to_remote_g2[i].addr.Clear();
		to_remote_g2[i].streamid = 0;
		to_remote_g2[i].last_time = 0;
	}

	/* where to send packets to qnlink */
	plug.Initialize(AF_INET, g2_link.port, g2_link.ip.c_str());

	printf("QnetGateway...entering processing loop\n");

	if (bool_send_qrgs)
		qrgs_and_maps();
	return false;
}

CQnetGateway::CQnetGateway()
{
	ii = NULL;
}

CQnetGateway::~CQnetGateway()
{
	if (srv_sock != -1) {
		close(srv_sock);
		printf("Closed G2_INTERNAL_PORT\n");
	}

	if (g2_sock != -1) {
		close(g2_sock);
		printf("Closed G2_EXTERNAL_PORT\n");
	}

	if (bool_send_aprs) {
		if (aprs->GetSock() != -1) {
			close(aprs->GetSock());
			printf("Closed APRS\n");
		}
		delete aprs;
	}

	for (int i=0; i<3; i++) {
		recd[i].last_time = 0;
		recd[i].streamid = 0;
		if (recd[i].fd >= 0) {
			close(recd[i].fd);
			unlink(recd[i].file);
		}
	}

	if (ii) {
		ii->close();
		delete ii;
	}

	printf("QnetGateway exiting\n");
}

bool CQnetGateway::validate_csum(SBANDTXT &bt, bool is_gps)
{
	const char *name = is_gps ? "GPS" : "GPRMC";
	char *s = is_gps ? bt.gpid : bt.gprmc;
	char *p = strrchr(s, '*');
	if (!p) {
		// BAD news, something went wrong
		printf("Missing asterisk before checksum in %s\n", name);
		bt.gprmc[0] = bt.gpid[0] = '\0';
		return true;
	} else {
		*p = '\0';
		// verify csum in GPRMC
		bool ok = verify_gps_csum(s + 1, p + 1);
		if (!ok) {
			printf("csum in %s not good\n", name);
			bt.gprmc[0] = bt.gpid[0] = '\0';
			return true;
		}
	}
	return false;
}

void CQnetGateway::gps_send(short int rptr_idx)
{
	time_t tnow = 0;
	static char old_mycall[CALL_SIZE + 1] = { "        " };

	if ((rptr_idx < 0) || (rptr_idx > 2)) {
		printf("ERROR in gps_send: rptr_idx %d is invalid\n", rptr_idx);
		return;
	}

	if (band_txt[rptr_idx].gprmc[0] == '\0') {
		band_txt[rptr_idx].gpid[0] = '\0';
		printf("missing GPS ID\n");
		return;
	}
	if (band_txt[rptr_idx].gpid[0] == '\0') {
		band_txt[rptr_idx].gprmc[0] = '\0';
		printf("Missing GPSRMC\n");
		return;
	}
	if (memcmp(band_txt[rptr_idx].gpid, band_txt[rptr_idx].lh_mycall, CALL_SIZE) != 0) {
		printf("MYCALL [%s] does not match first 8 characters of GPS ID [%.8s]\n", band_txt[rptr_idx].lh_mycall, band_txt[rptr_idx].gpid);
		band_txt[rptr_idx].gprmc[0] = '\0';
		band_txt[rptr_idx].gpid[0] = '\0';
		return;
	}

	/* if new station, reset last time */
	if (strcmp(old_mycall, band_txt[rptr_idx].lh_mycall) != 0) {
		strcpy(old_mycall, band_txt[rptr_idx].lh_mycall);
		band_txt[rptr_idx].gps_last_time = 0;
	}

	/* do NOT process often */
	time(&tnow);
	if ((tnow - band_txt[rptr_idx].gps_last_time) < 31)
		return;

	printf("GPRMC=[%s]\n", band_txt[rptr_idx].gprmc);
	printf("GPS id=[%s]\n",band_txt[rptr_idx].gpid);

	if (validate_csum(band_txt[rptr_idx], false))	// || validate_csum(band_txt[rptr_idx], true))
		return;

	/* now convert GPS into APRS and send it */
	build_aprs_from_gps_and_send(rptr_idx);

	band_txt[rptr_idx].is_gps_sent = true;
	time(&(band_txt[rptr_idx].gps_last_time));
	return;
}

void CQnetGateway::build_aprs_from_gps_and_send(short int rptr_idx)
{
	char buf[512];
	const char *delim = ",";

	char *saveptr = NULL;

	/*** dont care about the rest */

	strcpy(buf, band_txt[rptr_idx].lh_mycall);
	char *p = strchr(buf, ' ');
	if (p) {
		if (band_txt[rptr_idx].lh_mycall[7] != ' ') {
			*p = '-';
			*(p + 1) = band_txt[rptr_idx].lh_mycall[7];
			*(p + 2) = '>';
			*(p + 3) = '\0';
		} else {
			*p = '>';
			*(p + 1) = '\0';
		}
	} else
		strcat(buf, ">");

	strcat(buf, "APDPRS,DSTAR*,qAR,");
	strcat(buf, rptr.mod[rptr_idx].call.c_str());
	strcat(buf, ":!");

	//GPRMC =
	strtok_r(band_txt[rptr_idx].gprmc, delim, &saveptr);
	//time_utc =
	strtok_r(NULL, delim, &saveptr);
	//nav =
	strtok_r(NULL, delim, &saveptr);
	char *lat_str = strtok_r(NULL, delim, &saveptr);
	char *lat_NS = strtok_r(NULL, delim, &saveptr);
	char *lon_str = strtok_r(NULL, delim, &saveptr);
	char *lon_EW = strtok_r(NULL, delim, &saveptr);

	if (lat_str && lat_NS) {
		if ((*lat_NS != 'N') && (*lat_NS != 'S')) {
			printf("Invalid North or South indicator in latitude\n");
			return;
		}
		if (strlen(lat_str) > 9) {
			printf("Invalid latitude\n");
			return;
		}
		if (lat_str[4] != '.') {
			printf("Invalid latitude\n");
			return;
		}
		lat_str[7] = '\0';
		strcat(buf, lat_str);
		strcat(buf, lat_NS);
	} else {
		printf("Invalid latitude\n");
		return;
	}
	/* secondary table */
	strcat(buf, "/");

	if (lon_str && lon_EW) {
		if ((*lon_EW != 'E') && (*lon_EW != 'W')) {
			printf("Invalid East or West indicator in longitude\n");
			return;
		}
		if (strlen(lon_str) > 10) {
			printf("Invalid longitude\n");
			return;
		}
		if (lon_str[5] != '.') {
			printf("Invalid longitude\n");
			return;
		}
		lon_str[8] = '\0';
		strcat(buf, lon_str);
		strcat(buf, lon_EW);
	} else {
		printf("Invalid longitude\n");
		return;
	}

	/* Just this symbolcode only */
	strcat(buf, "/");
	strncat(buf, band_txt[rptr_idx].gpid + 13, 32);

	// printf("Built APRS from old GPS mode=[%s]\n", buf);
	strcat(buf, "\r\n");

	if (-1 == aprs->WriteSock(buf, strlen(buf))) {
		if ((errno == EPIPE) || (errno == ECONNRESET) || (errno == ETIMEDOUT) || (errno == ECONNABORTED) ||
		    (errno == ESHUTDOWN) || (errno == EHOSTUNREACH) || (errno == ENETRESET) || (errno == ENETDOWN) ||
		    (errno == ENETUNREACH) || (errno == EHOSTDOWN) || (errno == ENOTCONN)) {
			printf("build_aprs_from_gps_and_send: APRS_HOST closed connection, error=%d\n", errno);
			close(aprs->GetSock());
			aprs->SetSock( -1 );
		} else
			printf("build_aprs_from_gps_and_send: send error=%d\n", errno);
	}
	return;
}

bool CQnetGateway::verify_gps_csum(char *gps_text, char *csum_text)
{
	short computed_csum = 0;
	char computed_csum_text[16];

	short int len = strlen(gps_text);
	for (short int i=0; i<len; i++) {
		char c = gps_text[i];
		if (computed_csum == 0)
			computed_csum = (char)c;
		else
			computed_csum = computed_csum ^ ((char)c);
	}
	sprintf(computed_csum_text, "%02X", computed_csum);
	// printf("computed_csum_text=[%s]\n", computed_csum_text);

	char *p = strchr(csum_text, ' ');
	if (p)
		*p = '\0';

	if (strcmp(computed_csum_text, csum_text) == 0)
		return true;
	else
		return false;
}

int main(int argc, char **argv)
{
	printf("VERSION %s\n", VERSION);
	if (argc != 2) {
		printf("usage: %s <config file path>\n", argv[0]);
		return 1;
	}
	CQnetGateway QnetGateway;
	if (QnetGateway.Init(argv[1]))
		return 1;
	QnetGateway.Process();
	printf("Leaving processing loop...\n");
}
