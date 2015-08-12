#include "session.h"

#include <stdlib.h>

/*
 * Convinience function for creating a session_rec from the sniff_ip, sniff_tcp
 * and timeval structs. It allocated memory, so be sure to free the struct
 * returned, lest ye be haunted by memory leaks!
 */
struct session_rec* build_session(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts) {
    struct session_rec *sess;
    sess = malloc(sizeof(struct session_rec));
    sess->sport = tcp->th_sport;
    sess->dport = tcp->th_dport;
    sess->ip_src = ip->ip_src;
    sess->ip_dst = ip->ip_dst;
    sess->seq = tcp->th_seq;
    sess->ts = ts;
    return sess;
}
