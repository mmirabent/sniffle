#ifndef __PCM_OUTPUT_H
#define __PCM_OUTPUT_H

#include <pcap/pcap.h>
#include <arpa/inet.h>

void report_server_rtt(struct in_addr client, struct in_addr server, u_short sport, u_short dport, int rtt);
void reverse_dns_lookup(char * ip_addr, char * buffer);
int exec_cmd(char * cmd, char ** args, char * buffer);

#endif
