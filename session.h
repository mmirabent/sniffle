#ifndef __PCM_SESSION_H
#define __PCM_SESSION_H

#include "decode.h"

#define SYN_TABLE_SIZE 100

struct session_rec **syn_table;
u_int syn_table_idx;

#define ACK_TABLE_SIZE 100
struct session_rec **ack_table;
u_int ack_table_idx;

struct session_rec {
    struct  in_addr ip_src;         /* source and dest address */
    struct  in_addr ip_dst;
    tcp_seq seq;     /* Sequence number */
    u_short sport;   /* Destination port */
    u_short dport;   /* Source port */
    struct  timeval ts;
};

int calc_delta(struct timeval ts1, struct timeval ts2);
void add_to_syn(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void find_in_syn(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void add_to_ack(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
struct session_rec* find_in_ack(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
struct session_rec* build_session(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);

#endif
