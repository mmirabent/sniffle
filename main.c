/*
 * Copyright 2015 Marcos Mirabent
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


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

int main(int argc, char** argv) {
    /* Error buffer used by many pcap functions to return error messages */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *capture;
    char *dev;
    int ret;
    struct bpf_program *filter;

    /* ack_table = malloc(ACK_TABLE_SIZE * sizeof(struct session_rec*));
    for(int i = 0; i < ACK_TABLE_SIZE; i++){
        ack_table[i] = NULL;
    }
    ack_table_idx = 0; */
    init_ack();

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
    } else if(tcp->th_flags == TH_ACK) {
        find_in_ack(ip, tcp, h->ts);
    }
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


