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
 * \brief Output code
 */

#include "output.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUF_SIZE 1024

void reverse_dns_lookup(struct in_addr ip_addr, char* buffer, socklen_t buff_size);
int exec_cmd(char * cmd, char ** args, char * buffer);

/* 
 * At this point, this function just prints to stdout. However, this could be
 * changed to print to a file.
 */
void report_server_rtt(struct in_addr client, struct in_addr server, uint16_t sport, uint16_t dport, int rtt, int reverse_lookup) {
    char client_buf[BUF_SIZE], server_buf[BUF_SIZE];
    if(reverse_lookup) {
        reverse_dns_lookup(client, client_buf, BUF_SIZE);
        reverse_dns_lookup(server, server_buf, BUF_SIZE); 
    } else {
        inet_ntop(AF_INET, &client, client_buf, BUF_SIZE);
        inet_ntop(AF_INET, &server, server_buf, BUF_SIZE);
    }

    printf("%s:%d -> ", client_buf, ntohs(sport));
    printf("%s:%d %dms\n", server_buf, ntohs(dport), rtt);
}

/*
 * If reverse DNS flag is provided, we use getnameinfo() to perform the reverse
 * DNS lookup. Write to buffer provided.
 */
void reverse_dns_lookup(struct in_addr ip_addr, char* buffer, socklen_t buff_size){
  struct sockaddr_in sa;
  int res;

  sa.sin_family = AF_INET;
  sa.sin_addr = ip_addr;

  /* Final three arguments are NULL or 0 since we don't care about the server, servlen, or
   * flags */
  res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), buffer, buff_size, NULL, 0, 0);
  if(res){ /* TODO: Better error message */
    printf("things broke\n");
  }
}


