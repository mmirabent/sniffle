#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "decode.h"
#include "session.h"

void print_error(char* err);
void print_pcap_err(pcap_t *p);
void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void add_to_syn(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void add_to_ack(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void report_server_rtt(struct in_addr client, struct in_addr server, u_short sport, u_short dport, int rtt);
struct session_rec* build_session(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
struct session_rec* find_in_ack(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void find_in_syn(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);

#define ACK_TABLE_SIZE 100
struct session_rec **ack_table;
u_int ack_table_idx;

#define SYN_TABLE_SIZE 100
struct session_rec **syn_table;
u_int syn_table_idx;

int main(int argc, char** argv) {
    /* Error buffer used by many pcap functions to return error messages */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *capture;
    char *dev;
    int ret;
    struct bpf_program *filter;

    ack_table = malloc(ACK_TABLE_SIZE * sizeof(struct session_rec*));
    for(int i = 0; i < ACK_TABLE_SIZE; i++){
        ack_table[i] = NULL;
    }
    ack_table_idx = 0;

    syn_table = malloc(SYN_TABLE_SIZE * sizeof(struct session_rec*));
    for(int i = 0; i < SYN_TABLE_SIZE; i++){
        syn_table[i] = NULL;
    }
    syn_table_idx = 0;

    /* If no command line arguments given, lookup a device to open. Else use 
     * first argument */
    if(argc < 2)
        dev = pcap_lookupdev(errbuf);
    else
        dev = argv[1];

    /* If error occurs, print it and die*/
    if(!dev) print_error(errbuf);

    /* Create a pcap file handle for doing a live capture */
    capture = pcap_create(dev, errbuf); 
    if(!capture) print_error(errbuf);

    /* Set a short snapshot length, as all we want to see are the headers */
    pcap_set_snaplen(capture, 64); 

    /* Set to promiscuous mode */
    pcap_set_promisc(capture, 1);

    /* Set the read timeout in ms, this allows packets to buffer before waking 
       the application and processing them */
    pcap_set_timeout(capture, 50); 

    /* activate pcap handle. This must be done after the create. options
       should be set before calling this */
    ret = pcap_activate(capture);
    if(ret)
        print_pcap_err(capture);

    /* Set up the packet filter and compile it down */
    filter = malloc(sizeof(struct bpf_program));
    ret = pcap_compile(capture, filter, "tcp", 1, PCAP_NETMASK_UNKNOWN);
    if(ret)
        print_pcap_err(capture);

    ret = pcap_setfilter(capture, filter);
    if(ret)
        print_pcap_err(capture);

    /* Start reading packets */
    ret = pcap_loop(capture, 0, process_packet, NULL);
    if(ret)
        print_pcap_err(capture);

    return 0;
}

/*
 * This is the callback function used by pcal_loop to process packets. Packets
 * appear as byte arrays, here called 'packet' that are at most 'snap_len' long.
 * The actual length is stored in the pcap_pkthdr struct 'h'. We don't really
 * care becasue all we're interested in is the TCP and IP headers. The pragma
 * below is used to suppress warnings about the user pointer not being used.
 * The user pointer would allow pcap_loop to pass a pointer to the callback
 * function, but for our purposes it's uneccessary.
 */
#pragma GCC diagnostic ignored "-Wunused-parameter"
void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    /* declare the ip and tcp structs that will allow us to easily access the
     * data later */
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    int size_ip;
    int size_tcp;

    /* By casting the correct memory address to the ip and tcp structs, we can
     * use the structs to get at the important information in the packet headers */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if(size_ip < 20) return; /* Invalid IP header, die*/

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if(size_tcp < 20) return; /* Invalid TCP header, die*/

    /* This is where the magic starts */
    if(tcp->th_flags == TH_SYN) {   /* If the packet has the SYN flag set */
        add_to_syn(ip, tcp, h->ts); 
    } else if(tcp->th_flags == ( TH_SYN | TH_ACK )){ /* If the packet has the SYN and ACK flag set */
        find_in_syn(ip, tcp, h->ts);
        add_to_ack(ip, tcp, h->ts);
    } /* TODO: Add ack packet section */
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
 * Prints error messages and dies
 */
void print_error(char* err) {
    fprintf(stderr, "An error has occurred: %s\n", err);
    exit(1);
}

/*
 * Prints pcap specific error messages and dies
 */
void print_pcap_err(pcap_t *p) {
    print_error(pcap_geterr(p));
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
               delta = calc_delta(sess2->ts.tv_sec, sess2->ts.tv_usec, sess1->ts.tv_sec, sess1->ts.tv_usec);
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

int calc_delta(long int sec1, long int usec1, long int sec2, long int usec2){
  int delta_sec = sec2 - sec1;
  int delta_msec = (usec2 - usec1)/1000;
  return ((delta_sec)*1000 + delta_msec);
}

/* 
 * At this point, this function just prints to stdout. However, this could be
 * changed to print to a file.
 */
void report_server_rtt(struct in_addr client, struct in_addr server, u_short sport, u_short dport, int rtt) {
    printf("%s:%d -> ", inet_ntoa(client), sport);
    printf("%s:%d %dms\n", inet_ntoa(server), dport, rtt);
}

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


