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
#ifndef __PCM_OUTPUT_H
#define __PCM_OUTPUT_H

#include <pcap/pcap.h>
#include <arpa/inet.h>

void report_server_rtt(struct in_addr client, struct in_addr server, u_short sport, u_short dport, int rtt);

#endif
