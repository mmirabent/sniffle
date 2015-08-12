#include "output.h"

/* 
 * At this point, this function just prints to stdout. However, this could be
 * changed to print to a file.
 */
void report_server_rtt(struct in_addr client, struct in_addr server, u_short sport, u_short dport, int rtt) {
    printf("%s:%d -> ", inet_ntoa(client), sport);
    printf("%s:%d %dms\n", inet_ntoa(server), dport, rtt);
}
