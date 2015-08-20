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

/**
 * \file
 * \brief Packet decoding
 *
 * This file contains structs and macros for decoding TCP/IP packets.
 */

#ifndef __PCM_DECODE_H
#define __PCM_DECODE_H

#include <pcap/pcap.h>
#include <netinet/in.h>

/** Ethernet header size
 *
 * ethernet headers are always exactly 14 bytes
 */
#define SIZE_ETHERNET 14

/** Ethernet address size
 *
 * Ethernet addresses are 6 bytes 
 */
#define ETHER_ADDR_LEN  6

/**
 * Ethernet header
 *
 * This struct is for decoding the ethernet header of a packet
 */
struct sniff_ethernet {
    uint8_t ether_dhost[ETHER_ADDR_LEN]; /**< Destination host MAC address */
    uint8_t ether_shost[ETHER_ADDR_LEN]; /**< Source host MAC address */
    uint16_t ether_type;                 /**< Ethertype field */
};

/**
 * IP Header
 *
 * This struct is for decoding the IP packet header
 */
struct sniff_ip {
    /** Version and Header Length 
     *
     * The first two bits represent the version number. In order to access it, 
     * left shift four times `ip_vhl << 4`.
     *
     * The last four bits represent the length of the header. Access that by 
     * shifting right twice `ip_vhl >> 2`.
     */
    uint8_t  ip_vhl;                 
    uint8_t  ip_tos;                 /**< Type of service */
    uint16_t ip_len;                 /**< Total length of IP packet */
    uint16_t ip_id;                  /**< Identification */
    uint16_t ip_off;                 /**< Fragment offset field */
    #define IP_RF 0x8000             /**< Reserved fragment flag */
    #define IP_DF 0x4000             /**< Dont fragment flag */
    #define IP_MF 0x2000             /**< More fragments flag */
    #define IP_OFFMASK 0x1fff        /**< Mask for fragmenting bits */
    uint8_t  ip_ttl;                 /**< Time To Live */
    uint8_t  ip_p;                   /**< Protocol */
    uint16_t ip_sum;                 /**< Checksum */
    struct  in_addr ip_src;          /**< Source address */
    struct  in_addr ip_dst;          /**< Destination address */
};

/**
 * Calculate IP Header Length
 *
 * \param[in] ip A struct sniff_ip to calculate the header length of
 * \returns   Length of the IP header
 */
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
/**
 * IP Version
 *
 * \param[in] ip A scruct sniff_ip
 * \returns   4 or 6 for IPv4 or IPv6
 */
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/** TCP sequence number */
typedef unsigned int tcp_seq;

/**
 * TCP Header
 *
 * This struct is for decoding the TCP packet header.
 */
struct sniff_tcp {
    uint16_t th_sport;   /**< Source port */
    uint16_t th_dport;   /**< Destination port */
    tcp_seq th_seq;      /**< Sequence number */
    tcp_seq th_ack;      /**< Acknowledgment number */
    uint8_t  th_offx2;   /**< Data offset, rsvd */
    /**
     * Data Offset
     *
     * \param[in] th TCP header to calculate the data offset for
     */
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t  th_flags;   /**< Flags */
    #define TH_FIN  0x01 /**< FIN flag mask */
    #define TH_SYN  0x02 /**< SYN flag mask */
    #define TH_RST  0x04 /**< Reset flag mask */
    #define TH_PUSH 0x08 /**< PUSH flag mask */
    #define TH_ACK  0x10 /**< ACK flag mask */
    #define TH_URG  0x20 /**< URG flag mask */
    #define TH_ECE  0x40 /**< ECE flag mask */
    #define TH_CWR  0x80 /**< CWR flag mask */
    #define TH_FLAGS    (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR) /**< All TCP Header flags */
    uint16_t th_win;     /**< Window */
    uint16_t th_sum;     /**< Checksum */
    uint16_t th_urp;     /**< Urgent pointer */
};
#endif

