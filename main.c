#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

void print_error(char* err);
void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

int main(int argc, char** argv) {
    /* Error buffer used by many pcap functions to return error messages */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *capture;
    char *dev;
    int ret;

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
        print_error(pcap_geterr(capture));

    printf("The pcap_activate return value was %d\n", ret);

    /* Start reading packets */
    ret = pcap_loop(capture, 0, process_packet, '\0');
    printf("The pcap_loop return value was %d\n", ret);
    if(ret)
        print_error(pcap_geterr(capture));

    return 0;
}

void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    u_int i;
    printf("Packet\n");
    for(i = 0; i < h->caplen && i < h->len; i+=4)
        printf("%02x%02x%02x%02x\n", bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]);
}

void print_error(char* err) {
    fprintf(stderr, "An error has occurred: %s\n", err);
    exit(1);
}

