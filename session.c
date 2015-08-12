#include "session.h"
#include "output.h"

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

/*
 * This function allocated a new session_rec struct and then adds it to the
 * syn table. The syn_table_idx keeps track of position, and the modulo
 * operator is used to make sure that when the syn_table_idx reaches
 * SYN_TABLE_SIZE, the index wraps around to 0
 */
void add_to_syn(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts) {
    struct session_rec *sess = build_session(ip, tcp, ts);
    int i = syn_table_idx % SYN_TABLE_SIZE;

    free(syn_table[i]);
    syn_table[i] = sess;
    syn_table_idx++;
}

/*
 * This function looks for a matching SYN packet in the syn table. It takes the
 * sniff_ip and sniff_tcp structs of a SYN-ACK packet. If it finds a matching
 * SYN packet, it will call the report_server_rtt function and remove the 
 * matched SYN packet from the syn table.
 */
void find_in_syn(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts) {
    /* Build a session record from the supplied ip, tcp and ts structs.
     * Strictly speaking, this isn't necessary, but it makes the code below
     * neater and more straightforward to read */
    struct session_rec* sess2 = build_session(ip, tcp, ts);
    struct session_rec* sess1;
    int delta;

    for(int i = 0; i < SYN_TABLE_SIZE; i++) {
        sess1 = syn_table[i];
        /* Check that both structs are non-NULL and then match source ip to
         * destination ip and source port to destination port */
        if(sess1 && sess2 && 
                sess2->ip_src.s_addr == sess1->ip_dst.s_addr && 
                sess2->ip_dst.s_addr == sess1->ip_src.s_addr &&
                sess2->sport == sess1->dport &&
                sess2->dport == sess1->sport) {
            /* Match found, calculate delta */
           /*  delta = (sess2->ts.tv_usec - sess1->ts.tv_usec)/1000; */
               delta = calc_delta(sess1->ts, sess2->ts);
            report_server_rtt(sess1->ip_src, sess1->ip_dst, sess1->sport, sess1->dport, delta);

            /* Free the memory allocated and clear the space in the array to 
             * prevent double freeing memory later */
            free(sess2);
            free(sess1);
            syn_table[i] = NULL;
            return;
        }
    }
    free(sess2);
}

int calc_delta(struct timeval ts1, struct timeval ts2) {
    int delta_sec = (ts2.tv_sec - ts1.tv_sec)*1000;
    int delta_msec = (ts2.tv_usec - ts1.tv_usec)/1000;
    return (delta_sec + delta_msec);
}

/*
 * This function allocated a new session_rec struct and then adds it to the
 * ack table. The ack_table_idx keeps track of position, and the modulo
 * operator is used to make sure that when the ack_table_idx reaches
 * ACK_TABLE_SIZE, the index wraps around to 0
 */
void add_to_ack(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts) {
    struct session_rec *sess = build_session(ip, tcp, ts);
    int i = ack_table_idx % ACK_TABLE_SIZE;

    free(ack_table[i]);
    ack_table[i] = sess;
    ack_table_idx++;
}