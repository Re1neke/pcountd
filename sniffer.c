#include <sniffer.h>

iface_t cur_iface;
char next_dev[IFNAMSIZ + 1];

static void add_packet(uint32_t ip)
{
    ipstat_t tmp_stat;
    stortree_t *stor_node;
    statlist_t *stat_chain;
    int32_t pos;
    extern pthread_mutex_t mutex;

    tmp_stat.ip_addr = ip;
    tmp_stat.packet_count = 1;
    strncpy(tmp_stat.iface, cur_iface.dev_name, IFNAMSIZ);
    stor_node = get_stor_node(ip);
    if (stor_node != NULL) {
        stat_chain = get_if_stat(stor_node->stats, cur_iface.dev_name);
        if (stat_chain != NULL) {
            stat_chain->stat.packet_count++;
            update_file(stat_chain->pos, &stat_chain->stat);
        }
        else {
            pos = write_to_file(&tmp_stat);
            append_to_statlist(&stor_node->stats, &tmp_stat, (uint32_t)pos);
        }
    }
    else {
        pos = write_to_file(&tmp_stat);
        pthread_mutex_lock(&mutex);
        add_node_to_storage(&tmp_stat, (uint32_t)pos);
        pthread_mutex_unlock(&mutex);
    }
}

static void packet_handler(u_char *user_arg,
                            const struct pcap_pkthdr *header,
                            const u_char *packet
)    
{
    struct ethhdr  *eth_header;
    struct iphdr *ip_header;

    eth_header = (struct ethhdr *)packet;
    if (htons(eth_header->h_proto) != ETH_P_IP)
        return ;
    ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    add_packet(htonl(ip_header->saddr));
}

void *sniff_iface(void *arg)
{
    while (true) {
        if (!cur_iface.sniff)
            continue ;
        pcap_activate(cur_iface.pcap_handler);
        pcap_setdirection(cur_iface.pcap_handler, PCAP_D_IN);
        pcap_loop(cur_iface.pcap_handler, 0, &packet_handler, NULL);
    }
    return (NULL);
}

int select_iface(char *dev)
{
    pcap_if_t *alldevsp, *tmpdevp;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (dev == NULL)
        return (-1);
    if (pcap_findalldevs(&alldevsp, errbuf) == -1)
        return (-1);
    tmpdevp = alldevsp;
    while (tmpdevp != NULL) {
        if ((tmpdevp->flags & PCAP_IF_UP) && !strcmp(dev, tmpdevp->name)) {
            strncpy(next_dev, dev, IFNAMSIZ);
            pcap_freealldevs(alldevsp);
            return (0);
        }
        tmpdevp = tmpdevp->next;
    }
    pcap_freealldevs(alldevsp);
    return (1);
}

int set_iface(void)
{
    pcap_t *tmp_handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;

    if (strlen(next_dev) <= 0)
        dev = pcap_lookupdev(errbuf);
    else
        dev = next_dev;
    if (dev == NULL)
        return (-1);
    tmp_handler = pcap_create(dev, errbuf);
    if (tmp_handler == NULL)
        return (-1);
    cur_iface.pcap_handler = tmp_handler;
    strncpy(cur_iface.dev_name, dev, IFNAMSIZ);
    cur_iface.sniff = true;
    return (0);
}

int unset_iface(void)
{
    if (cur_iface.pcap_handler != NULL) {
        pcap_breakloop(cur_iface.pcap_handler);
        pcap_close(cur_iface.pcap_handler);
    }
    memset(cur_iface.dev_name, 0, IFNAMSIZ + 1);
    cur_iface.sniff = false;
    return (0);
}