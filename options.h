#ifndef __PCM_OPTIONS_H
#define __PCM_OPTIONS_H

extern int reverse_dns_flag;
extern char* live_capture_dev;
extern char* capture_file;
extern char* csv_output_file;
extern int size;

void process_options(int argc, char** argv);

#endif
