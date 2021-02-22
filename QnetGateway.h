/*
 *   Copyright (C) 2018-2019 by Thomas Early N7TAE
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

#include <set>
#include <map>
#include <string>
#include <regex>

#include "QnetTypeDefs.h"
#include "SEcho.h"
#include "QnetDB.h"
#include "aprs.h"
#include "DStarDecode.h"
#include "SockAddress.h"
#include "Location.h"

#define IP_SIZE 15
#define MAXHOSTNAMELEN 64
#define CALL_SIZE 8
#define MAX_DTMF_BUF 32

using STOREMOTEG2 = struct to_remote_g2_tag {
	unsigned short streamid;
	CSockAddress addr;
	time_t last_time;
};

using STOREPEATER = struct torepeater_tag {
	// help with header re-generation
	SDSTR saved_hdr; // repeater format
	CSockAddress saved_adr;

	unsigned short streamid;
	CSockAddress adr;
	CSockAddress addr;
	time_t last_time;
	std::atomic<unsigned short> G2_COUNTER;
	unsigned char sequence;
};

using SBANDTXT = struct band_txt_tag {
	unsigned short streamID;
	unsigned char flags[3];
	char lh_mycall[CALL_SIZE + 1];
	char lh_sfx[5];
	char lh_yrcall[CALL_SIZE + 1];
	char lh_rpt1[CALL_SIZE + 1];
	char lh_rpt2[CALL_SIZE + 1];
	time_t last_time;
	char txt[64];   // Only 20 are used
	unsigned short txt_cnt;
	bool sent_key_on_msg;

	std::string dest_rptr;

	// try to process GPS mode: GPRMC and ID
	char temp_line[256];
	unsigned short temp_line_cnt;
	char gprmc[256];
	char gpid[256];
	bool is_gps_sent;
	time_t gps_last_time;

	int num_dv_frames;
	int num_dv_silent_frames;
	int num_bit_errors;
};

using SSD = struct sd_tag {
	unsigned char header[41];
	unsigned char message[21];
	unsigned char gps[256];
	unsigned int ih, im, ig;
	unsigned char type;
	bool first;
	unsigned int size;
	void Init() { ih = im = ig = 0; first = true; }
};

class CQnetGateway {
public:
	CQnetGateway();
	~CQnetGateway();
	void Process();
	bool Init(char *cfgfile);

private:
	// text stuff
	bool new_group[3] = { true, true, true };
	unsigned char header_type = 0;
	short to_print[3] = { 0, 0, 0 };
	bool ABC_grp[3] = { false, false, false };
	bool C_seen[3] = { false, false, false };

	SPORTIP g2_internal, g2_external, g2_link, ircddb;

	std::string OWNER, owner, dtmf_dir, dtmf_file, echotest_dir, irc_pass, qnvoicefile, DASH_SHOW_ORDER, DASH_SQL_NAME;

	bool bool_send_qrgs, bool_irc_debug, bool_log_debug, bool_dtmf_debug, bool_regen_header, bool_qso_details, bool_send_aprs, playNotInCache, showLastHeard;

	int play_wait, play_delay, echotest_rec_timeout, voicemail_rec_timeout, from_remote_g2_timeout, from_local_rptr_timeout, dtmf_digit;

	int avalidmodule;

	unsigned int vPacketCount;

	std::map <std::string, unsigned short> portmap;
	std::set<std::string> findRoute;

	// data needed for aprs login and aprs beacon
	// RPTR defined in aprs.h
	SRPTR rptr;

	// local repeater modules being recorded
	// This is for echotest and voicemail
	SECHO recd[3], vm[3];
	SDSVT recbuf; // 56 or 27, max is 56

	// the streamids going to remote Gateways from each local module
	STOREMOTEG2 to_remote_g2[3]; // 0=A, 1=B, 2=C

	// input from remote G2 gateway
	int g2_sock = -1;
	CSockAddress fromDst4;

	// Incoming data from remote systems
	// must be fed into our local repeater modules.
	STOREPEATER toRptr[3]; // 0=A, 1=B, 2=C

	// input from our own local repeater modules
	int srv_sock = -1;
	SDSTR rptrbuf; // 58 or 29 or 32, max is 58
	CSockAddress fromRptr;

	SDSTR end_of_audio;

	// send packets to g2_link
	CSockAddress plug;

	// for talking with the irc server
	CIRCDDB *ii;
	// for handling APRS stuff
	CAPRS *aprs;

	SSD Sd[4];
	SDSTR sdheader;
	CLocation gps;

	// sqlite3 database
	CQnetDB qnDB;

	// DStar decoder
	CDStarDecode dstar_decode;

	// text coming from local repeater bands
	SBANDTXT band_txt[3]; // 0=A, 1=B, 2=C

	/* Used to validate MYCALL input */
	std::regex preg;

	pthread_mutex_t irc_data_mutex = PTHREAD_MUTEX_INITIALIZER;

	int open_port(const SPORTIP &pip);
	void calcPFCS(unsigned char *packet, int len);
	void GetIRCDataThread();
	int get_yrcall_rptr_from_cache(const std::string &call, std::string &rptr, std::string &gate, std::string &addr, char RoU);
	bool get_yrcall_rptr(const std::string &call, std::string &rptr, std::string &gate, std::string &addr, char RoU);
	void PlayFileThread(SECHO &edata);
	void compute_aprs_hash();
	void APRSBeaconThread();
	void ProcessTimeouts();
	void ProcessSlowData(unsigned char *data, unsigned short sid);
	void ProcessIncomingSD(const SDSVT &dsvt);
	bool ProcessG2Msg(const unsigned char *data, const int mod, std::string &smrtgrp);
	bool Flag_is_ok(unsigned char flag);
	void UnpackCallsigns(const std::string &str, std::set<std::string> &set, const std::string &delimiters = ",");
	void PrintCallsigns(const std::string &key, const std::set<std::string> &set);
	bool Printable(unsigned char *s);
	bool VoicePacketIsSync(const unsigned char *text) const;

	// read configuration file
	bool read_config(char *);

/* aprs functions, borrowed from my retired IRLP node 4201 */
	void gps_send(short int rptr_idx);
	bool verify_gps_csum(char *gps_text, char *csum_text);
	void build_aprs_from_gps_and_send(short int rptr_idx);

	void qrgs_and_maps();

	void set_dest_rptr(const char mode, std::string &call);
	bool validate_csum(SBANDTXT &bt, bool is_gps);
};
