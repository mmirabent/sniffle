#ifndef __PCM_OUTPUT_H
#define __PCM_OUTPUT_H

#include <pcap/pcap.h>
#include <arpa/inet.h>

void report_server_rtt(struct in_addr client, struct in_addr server, u_short sport, u_short dport, int rtt);

#endif
