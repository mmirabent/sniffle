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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "options.h"

int reverse_dns_flag;
char* live_capture_dev;
char* capture_file;
char* csv_output_file;
int size;

void process_options(int argc, char** argv) {
    int c;
    live_capture_dev = NULL;
    capture_file = NULL;
    size = 100; /* Default table size */
    while(1) {
        static struct option long_options[] = 
        {
            {"reverse-dns",  no_argument,       0, 'n'},
            {"live-capture", required_argument, 0, 'l'},
            {"file-input",   required_argument, 0, 'f'},
            {"csv-output",   required_argument, 0, 'o'},
            {"size",         required_argument, 0, 's'},
            {"help",         no_argument,       0, 'h'},
            {0,0,0,0}
        };

        int option_index = 0;
        char *end;

        c = getopt_long(argc, argv, "nhl:f:o:s:", long_options, &option_index);


        if(c == -1) break; /* End of options */

        switch(c) {
            case 'n':
                reverse_dns_flag = 1;
                break;
            case 'l':
                live_capture_dev = optarg;
                break;
            case 'f':
                capture_file = optarg;
                break;
            case 'o':
                csv_output_file = optarg;
                break;
            case 's':
                size = strtol(optarg, &end, 10);
                if(errno == ERANGE) { /* Too large a number */
                    fprintf(stderr, "Size supplied is too large");
                    exit(-1);
                } else if(!size && end == optarg) { /* No conversion */
                    fprintf(stderr, "The size argument must be a valid integer\n");
                    exit(-2);
                } else if(size <= 0) {
                    fprintf(stderr, "Size cannot be negative\n");
                    exit(-3);
                }
                break;
            case 'h':
                printf("usage: ./main [-l | -f input.pcap] [-o output.csv] [-s value] [-n] [-h] \n");
                printf("-l live capture\n");
                printf("-f packet capture\n");
                printf("-o csv output\n");
                printf("-n reverse-dns");
                printf("-s number of half open connections tracked\n");
                printf("-h help and usage\n");
                break;
        }
    }
}

