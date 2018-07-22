#include <sniffer.h>

extern bool is_cli;

char *itoipstr(const uint32_t *ip)
{
    static char ipstr[16];
    uint8_t *ip_oct;

    ip_oct = (uint8_t *)ip;
    sprintf(ipstr, "%hhu.%hhu.%hhu.%hhu",
        ip_oct[3], ip_oct[2], ip_oct[1], ip_oct[0]);
    return (ipstr);
}

uint32_t ipstrtoi(const char *ipstr)
{
    uint32_t ip;
    uint8_t *ip_oct;
    int read;

    ip_oct = (uint8_t *)(&ip);
    read = sscanf(ipstr, "%hhu.%hhu.%hhu.%hhu",
        &ip_oct[3], &ip_oct[2], &ip_oct[1], &ip_oct[0]);
    if (read != 4)
        return (0);
    return (ip);
}


void print_ipcount(statlist_t *ip_list)
{
    size_t total = 0;

    if (ip_list == NULL) {
        printf("No statistics was found.\n");
        return ;
    }
    printf("Statistics of incoming packets from %s:\n",
            itoipstr(&ip_list->stat.ip_addr));
    while (ip_list != NULL) {
        printf("\t%8s: %zu\n", ip_list->stat.iface, ip_list->stat.packet_count);
        total += ip_list->stat.packet_count;
        ip_list = ip_list->next;
    }
    printf("Total: %zu\n", total);
}

void print_ifacestat(if_list_t *if_list)
{
    statlist_t *cur_stat;

    if (if_list == NULL) {
        printf("No statistics was found.\n");
        return ;
    }
    while (if_list != NULL) {
        printf("Statistics for %s:\n", if_list->stats->stat.iface);
        cur_stat = if_list->stats;
        while (cur_stat != NULL) {
            printf("\t%16s : %zu\n", itoipstr(&cur_stat->stat.ip_addr),
                    cur_stat->stat.packet_count);
            cur_stat = cur_stat->next;
        } 
        if_list = if_list->next;
    }
}
