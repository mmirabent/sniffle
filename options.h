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
 * \brief Options header file
 *
 * Contains function headers for command line flag parsing and global variables
 * to indicate command line flags parsed
 */

#ifndef __PCM_OPTIONS_H
#define __PCM_OPTIONS_H

extern int reverse_dns_flag;
extern char* live_capture_dev;
extern int live_capture_flag;
extern char* capture_file;
extern char* csv_output_file;
extern unsigned int size_arg;

void print_usage(void);
void process_options(int argc, char** argv);

#endif
