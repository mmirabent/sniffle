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

#include <netinet/ip.h>

struct session_rec {
    struct  in_addr ip_src;         /* source and dest address */
    struct  in_addr ip_dst;
    uint16_t sport;   /* Destination port */
    uint16_t pad1;
    uint16_t dport;   /* Source port */
    uint16_t pad2;
    struct  timeval ts;
};

int calc_delta(struct timeval ts1, struct timeval ts2);
void add_to_syn(struct session_rec *sess);
void add_to_ack(struct session_rec *sess);
void find_in_syn(struct session_rec *sess);
void find_in_ack(struct session_rec *sess);
void init_ack(unsigned int size);
void init_syn(unsigned int size);
struct session_rec* build_session(struct in_addr src_addr, struct in_addr dst_addr, uint16_t src_port, uint16_t dst_port, struct timeval ts);

#endif
