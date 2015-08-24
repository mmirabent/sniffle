/*
 * Copyright 2015 Percussive Maintenance
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

/** \file main.c
 *  \brief Entry point
 *
 *  This is where the main function resides and where execution starts
 */


#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "decode.h"
#include "session.h"
#include "options.h"

void print_error(const char* err) __attribute__((noreturn));
void print_pcap_err(pcap_t *p) __attribute__((noreturn));
void process_packet(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes);
void check_for_root(void);
void set_live_capture_options(pcap_t* capture);

int main(int argc, char** argv) {
    /* Error buffer used by many pcap functions to return error messages */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *capture;
    char *dev;
    int ret;
    struct bpf_program *filter;

    /* If not enough options, print usage and die */
    if(argc < 2) {
        print_usage();
        return(-1);
    }

    /* Process options, see options.c */
    process_options(argc, argv);

    /* Set up the capture handle */
    capture = NULL;
    if(live_capture_flag) {
        /* If we're doing a live capture, we need root */
        check_for_root();
        
        /* If a device was supplied use it, otherwise lookup one */
        if(live_capture_dev) dev = live_capture_dev;
        else dev = pcap_lookupdev(errbuf);
        
        /* If dev is null, something went wrong with pcap_lookupdev */
        if(!dev) print_error(errbuf);

        /* Create a pcap file handle for doing a live capture */
        capture = pcap_create(dev, errbuf); 
        if(!capture) print_error(errbuf);

        /* Set options and activate capture device */
        set_live_capture_options(capture);

    } else if (capture_file) {
        /* Open an offline capture from the provided filename. The
         * pcap_open_offline function will do existence and permission checks
         * for us, and provide a helpful error message in errbuf if needed
         */
        capture = pcap_open_offline(capture_file, errbuf);
        if(!capture) print_error(errbuf);

    } else {
        /* We have neither a live capture nor a capture file. Print a useful
         * error message, then usage, then die */
        fprintf(stderr, "No live capture device or capture file specified\n");
        print_usage();
    }
    
    /* Sanity check, capture should be set at this point */
    if(!capture) print_error("Something is terribly wrong, no capture device or file");

    init_ack(size_arg);
    init_syn(size_arg);



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

/**
 * \brief callback function for pcap_loop
 *
 * This is the callback function used by pcap_loop to process packets. Packets
 * appear as byte arrays, here called `packet` that are at most `snap_len` long.
 * The actual length is stored in the pcap_pkthdr struct `h`. We don't really
 * care becasue all we're interested in is the TCP and IP headers. The pragma
 * below is used to suppress warnings about the `user` pointer not being used.
 * The `user` pointer would allow `pcap_loop` to pass a pointer to the callback
 * function, but for our purposes it's uneccessary.
 *
 * \param[in] user          A user defined byte pcap_loop will pass to the
 *                          callback function. We're not using it here.
 * \param[in] pcap_pkthdr   The pcap packet header, includes layer 1 info as 
 *                          as well as timestamps.
 * \param[in] packet        The binary data of the packet itself.
 */
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void process_packet(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *packet) {
    /* declare the ip and tcp structs that will allow us to easily access the
     * data later */
    const struct sniff_ip *ip;
    const struct sniff_tcp *tcp;
    int size_ip;
    int size_tcp;
    struct session_rec *sess;

    /* By casting the correct memory address to the ip and tcp structs, we can
     * use the structs to get at the important information in the packet headers */
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if(size_ip < 20) return; /* Invalid IP header, die*/

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if(size_tcp < 20) return; /* Invalid TCP header, die*/
#pragma clang diagnostic pop

    /* This is where the magic starts */
    if(tcp->th_flags == TH_SYN) {   /* If the packet has the SYN flag set */
        sess = build_session(ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport, h->ts);
        add_to_syn(sess);
    } else if(tcp->th_flags == ( TH_SYN | TH_ACK )){ /* If the packet has the SYN and ACK flag set */
        sess = build_session(ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport, h->ts);
        find_in_syn(sess);
        sess = build_session(ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport, h->ts);
        add_to_ack(sess);
    } else if(tcp->th_flags == TH_ACK) {
        sess = build_session(ip->ip_src, ip->ip_dst, tcp->th_sport, tcp->th_dport, h->ts);
        find_in_ack(sess);
    }
}
#pragma clang diagnostic pop

/**
 * \brief Prints error messages and dies
 *
 * This function will print to stderr the string "An error has occurred: "
 * followed by the provided string err. It then exits with status code 1
 *
 * \param[in] err A String to print
 */
void print_error(const char* err) {
    fprintf(stderr, "An error has occurred: %s\n", err);
    exit(1); /* TODO: Make this a function argument */
}

/**
 * \brief Prints pcap specific error messages and dies
 *
 * This function calls into the pcap library to extract an error message for a
 * pcap_t object, print it to stderr as print_error does and exit with status
 * code 1
 *
 * \param[in] p pcap_t object to print error for
 */
void print_pcap_err(pcap_t *p) {
    print_error(pcap_geterr(p));
}

/**
 * \brief Check for root
 *
 * This function checks to see if the program is bring run as root. If not, it
 * prints an error message and exits with status code -1
 */
void check_for_root() {
    uid_t uid, euid;

    uid = getuid();
    euid = geteuid();

    if(uid != 0 && euid != 0){
      fprintf(stderr, "Please run as root!\n");
      exit(-1);
    }
}

/**
 * \brief Sets up live capture
 *
 * This function sets options on the pcap_t handle that are relevant for a live
 * capture. It's important not to call this function on an offline pcap_t
 * handle, as it will fail.
 *
 * The options it sets limit the amount of the ethernet frame that is captured 
 * and passed into userland, enable promiscuous mode, set a read timeout and
 * activats the pcap_t object, enabling pcap_loop to use it
 *
 * \param[in] capture The live, unactivated pcap_t object to set options on
 */
void set_live_capture_options(pcap_t* capture) {
    int ret;

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
}

