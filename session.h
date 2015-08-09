#ifndef __PCM_SESSION_H
#define __PCM_SESSION_H

struct session_rec {
    struct  in_addr ip_src;         /* source and dest address */
    struct  in_addr ip_dst;
    tcp_seq seq;     /* Sequence number */
    u_short sport;   /* Destination port */
    u_short dport;   /* Source port */
    struct  timeval ts;
};
#endif
