#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "decode.h"

void print_error(char* err);
void print_pcap_err(pcap_t *p);
void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

int main(int argc, char** argv) {
    /* Error buffer used by many pcap functions to return error messages */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *capture;
    char *dev;
    int ret;
    struct bpf_program *filter;

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

    pcap_setfilter(capture, filter);
    if(ret)
        print_pcap_err(capture);

    /* Start reading packets */
    ret = pcap_loop(capture, 0, process_packet, NULL);
    if(ret)
        print_pcap_err(capture);

    return 0;
}

#pragma GCC diagnostic ignored "-Wunused-parameter"
void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    /* declare the ip and tcp structs that will allow us easy access to the data
     * later */
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    int size_ip;
    int size_tcp;

    /* By asigning the correct memory address to the ip and tcp structs, we can
     * use the structs to get at the important information in the packet headers */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if(size_ip < 20) return; /* Invalid IP header */

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if(size_tcp < 20) return; /* Invalid tcp header */

    printf("%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport)); 
    printf("%s:%d\n",  inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
    /* If SYN, add to syn table */
    /* If SYN-ACK, match with syn table entry, create delta, ship off for 
     * processing elsewhere(file IO for now). Then create entry in synack table*/
    /* If ACK, attempt to match with synack table entry, create delta, ship off for processing */

    /* syn table should have source ip, dest ip, source port, dest port, and syn-number */
    /* syn-ack table should have source ip, dest ip, source port, dest port, and syn-number */
    /* match by comparing ack-number+1 to syn number in table */

}

void print_error(char* err) {
    fprintf(stderr, "An error has occurred: %s\n", err);
    exit(1);
}

void print_pcap_err(pcap_t *p) {
    print_error(pcap_geterr(p));
}
