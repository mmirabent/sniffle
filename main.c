#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

void print_error(char* err);

int main(void) {
    /* Error buffer used by many pcap functions to return error messages */
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Lookup a device to open
       char* dev = pcap_lookupdev(errbuf); */
    char *dev = pcap_lookupdev(errbuf);
    if(!dev) print_error(errbuf);
    printf("%s\n", dev);

    /* Create a pcap file handle for doing a live capture
    pcap_create(); */

    /* Set a short snapshot length, as all we want to see are the headers
    pcap_set_snaplen(); */

    /* Set to promiscuous mode
    pcap_set_promisc(); */

    /* Set the read timeout, this allows packets to buffer before waking the
       application and processing them
    pcap_set_timeout(); */

    /* Set the timestamp type. The timestamp is set by the system, but we can
       choose what type of timestamp is applied with this. See pcap-tstamp(7)
    pcap_set_tstamp_type(); */

    /* activate pcap handle. This must be done after the create. options
       should be set before calling this
    pcap_activate(); */
    return 0;
}

void print_error(char* err) {
    fprintf(stderr, "An error has occurred: %s\n", err);
    exit(1);
}

