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

#define BUF_SIZE 1024

void report_server_rtt(struct in_addr client, struct in_addr server, u_short sport, u_short dport, int rtt);
void reverse_dns_lookup(char * ip_addr, char * buffer);
int exec_cmd(char * cmd, char ** args, char * buffer);

/* 
 * At this point, this function just prints to stdout. However, this could be
 * changed to print to a file.
 */

void report_server_rtt(struct in_addr client, struct in_addr server, u_short sport, u_short dport, int rtt) {
    char client_buf[BUF_SIZE], server_buf[BUF_SIZE];
    client_buf[BUF_SIZE - 1] = 0;
    server_buf[BUF_SIZE - 1] = 0;
    reverse_dns_lookup(inet_ntoa(client), client_buf);
    reverse_dns_lookup(inet_ntoa(server), server_buf);
    printf("%s:%d -> ", inet_ntoa(client), sport);
    printf("%s:%d %dms\n", inet_ntoa(server), dport, rtt);
 /*   printf("%s -> ", client_buf);
    printf("%s\n", server_buf); */
}

void reverse_dns_lookup(char * ip_addr, char * buffer){
  char dig_buf[BUF_SIZE], grep_buf[BUF_SIZE];
  dig_buf[BUF_SIZE -1] = 0;
  grep_buf[BUF_SIZE - 1] = 0;
  int buf_len = 0;

  char * dig_args[] = { "dig", "-x", ip_addr, "+short", NULL};
  buf_len = exec_cmd("dig", dig_args, dig_buf);

  char * grep_args[] = { "grep", "-o", "[a-zA-Z].*", "<<<", dig_buf};
  buf_len = exec_cmd("grep", grep_args, grep_buf);

  strncpy(buffer, grep_buf, buf_len);
  buffer[buf_len-1] = 0;
}

int exec_cmd(char * cmd, char ** args, char * buffer){
  int pipefd[2];
  int status;
  int i;
  int len = 0;
  char output[BUF_SIZE];
  pipe(pipefd);
  //printf("Cmd is %s %s %s %s %s\n", args[0], args[1], args[2], args[3], args[4]);

  pid_t pid = fork();
  if(pid == 0){
    close(pipefd[0]);
    dup2(pipefd[1],1);
    close(pipefd[1]);
    execvp(cmd, args);
    exit(0);
  }

  else{
    close(pipefd[1]);
    while(read(pipefd[0], output, BUF_SIZE) != 0){
    }

    for(i = 0; i < BUF_SIZE; i++){
      if(output[i] != 0){
        len++;
      }
    }
    waitpid(pid, &status, 0);
  }
    strncpy(buffer, output, len);
    buffer[len-1] = 0;
    return len;
}


