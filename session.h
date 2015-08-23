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
 * \brief Session handling
 *
 * This file documents session handling and tracking. It calls upon the output
 * code as well to record round trip times
 */

#ifndef __PCM_SESSION_H
#define __PCM_SESSION_H

#include "decode.h"

#define SYN_TABLE_SIZE 100
extern struct session_rec **syn_table;
extern u_int syn_table_idx;


struct session_rec {
    struct  in_addr ip_src;         /* source and dest address */
    struct  in_addr ip_dst;
    tcp_seq seq;     /* Sequence number */
    u_short sport;   /* Destination port */
    u_short dport;   /* Source port */
    struct  timeval ts;
};

int calc_delta(struct timeval ts1, struct timeval ts2);
void add_to_syn(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void add_to_ack(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void find_in_syn(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void find_in_ack(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);
void init_ack(void);
void init_syn(void);
struct session_rec* build_session(const struct sniff_ip* ip, const struct sniff_tcp* tcp, struct timeval ts);

#endif
