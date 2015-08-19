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
#include "output.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUF_SIZE 1024

void report_server_rtt(struct in_addr client, struct in_addr server, uint16_t sport, uint16_t dport, int rtt);
void reverse_dns_lookup(char * ip_addr, char * buffer);
int exec_cmd(char * cmd, char ** args, char * buffer);

/* 
 * At this point, this function just prints to stdout. However, this could be
 * changed to print to a file.
 */

void report_server_rtt(struct in_addr client, struct in_addr server, uint16_t sport, uint16_t dport, int rtt) {
    char client_buf[BUF_SIZE], server_buf[BUF_SIZE];
    client_buf[BUF_SIZE - 1] = 0;
    server_buf[BUF_SIZE - 1] = 0;
  /*  reverse_dns_lookup(inet_ntoa(client), client_buf);
    reverse_dns_lookup(inet_ntoa(server), server_buf); */
    printf("%s:%d -> ", inet_ntoa(client), sport);
    printf("%s:%d %dms\n", inet_ntoa(server), dport, rtt);
  /*  printf("%s -> ", client_buf);
    printf("%s\n", server_buf); */
}

/*
 * If reverse DNS flag is provided, we use getnameinfo() to perform the reverse
 * DNS lookup. Write to buffer provided.
 */

void reverse_dns_lookup(char * ip_addr, char * buffer){
  struct sockaddr_in sa;
  char node[NI_MAXHOST];
  int res;
  sa.sin_family = AF_INET;
  inet_pton(AF_INET, ip_addr, &sa.sin_addr);

  /* Final three arguments are NULL or 0 since we don't care about the server, servlen, or
   * flags */
  res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), node, sizeof(node), NULL, 0, 0);
  if(res){ /* TODO: Better error message */
    printf("things broke\n");
  }
  strncpy(buffer, node, NI_MAXHOST);
}


