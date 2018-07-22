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

// int print_ipcount(uint32_t ip)
// {
//     const memstor_t *ipstat;
//     size_t total = 0;
//     int count = 0; 

//     if (read_pidfile() > 0 && is_cli == true)
//         reload_file();
//     ipstat = get_ip_from_memstor(ip);
//     if (ipstat == NULL)
//         return (0);
//     printf("Statistics of incoming packets from %s:\n", itoipstr(&ip));
//     while (ipstat != NULL) {
//         printf("\t%8s: %zu\n", ipstat->stat.iface, ipstat->stat.packet_count);
//         total += ipstat->stat.packet_count;
//         count++;
//         ipstat = ipstat->next;
//     }
//     printf("Total: %zu\n", total);
//     return (count);
// }

// static int print_ifacelist(memstor_t *ifacelist)
// {
//     memstor_t *tmp_p;
//     int count = 0;

//     if (ifacelist != NULL)
//         printf("Statistics for %s:\n", ifacelist->stat.iface);
//     while (ifacelist != NULL) {
//         printf("\t%16s : %zu\n", itoipstr(&ifacelist->stat.ip_addr),
//             ifacelist->stat.packet_count);
//         tmp_p = ifacelist;
//         ifacelist = ifacelist->next;
//         free(tmp_p);
//         count++;
//     }
//     return (count);
// }

// int print_ifacestat(char *iface_name)
// {
//     memstor_t *ifacelist;
//     int count;

//     if (read_pidfile() > 0 && is_cli == true)
//         reload_file();
//     if (iface_name == NULL)
//         return (-1);
//     ifacelist = get_iface_from_memstor(iface_name);
//     count = print_ifacelist(ifacelist);
//     if (count <= 0)
//         printf("No statistics for %s was found.\n", iface_name);
//     return (count);
// }

// int print_allifacestat(void)
// {
//     if_list_t *ifaces, *tmp_p;

//     if (read_pidfile() > 0 && is_cli == true)
//         reload_file();
//     ifaces = get_iface_sorted_list();
//     if (ifaces == NULL) {
//         printf("No statistics was found.\n");
//         return (0);
//     }
//     while (ifaces != NULL) {
//         print_ifacelist(ifaces->list);
//         tmp_p = ifaces;
//         ifaces = ifaces->next;
//         free(tmp_p);
//     }
//     free(ifaces);
//     return (0);
// }
