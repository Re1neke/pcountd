#include <sniffer.h>

iface_t cur_iface;

static void add_packet(uint32_t ip)
{
    ipstat_t stat;
    stortree_t *stor;
    int32_t pos;

    stor = get_stor_node(ip, cur_iface.dev_name);
    if (stor != NULL) {
        stor->stat.packet_count++;
        update_file(stor->pos, &stor->stat);
    }
    else {
        stat.ip_addr = ip;
        stat.packet_count = 1;
        strncpy(stat.iface, cur_iface.dev_name, IFNAMSIZ);
        pos = write_to_file(&stat);
        add_to_storage(&stat, (uint32_t)pos);
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

void sniff_iface(void)
{
    pcap_activate(cur_iface.pcap_handler);
    pcap_setdirection(cur_iface.pcap_handler, PCAP_D_IN);
    pcap_loop(cur_iface.pcap_handler, 0, &packet_handler, NULL);
}

int change_iface(char *dev)
{
    pcap_if_t *alldevsp, *tmpdevp;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (dev == NULL)
        return (-1);
    if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
        fprintf(stderr, "Can not open device list: %s\n", errbuf);
        return (-1);
    }
    tmpdevp = alldevsp;
    while (tmpdevp != NULL) {
        if ((tmpdevp->flags & PCAP_IF_UP) && !strcmp(dev, tmpdevp->name)) {
            set_iface(dev);
            pcap_freealldevs(alldevsp);
            return (0);
        }
        tmpdevp = tmpdevp->next;
    }
    pcap_freealldevs(alldevsp);
    return (1);
}

int set_iface(char *dev)
{
    pcap_t *tmp_handler;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (dev == NULL)
        dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Can not find default device: %s\n", errbuf);
        return (-1);
    }
    tmp_handler = pcap_create(dev, errbuf);
    if (tmp_handler == NULL) {
        fprintf(stderr, "Can not open device: %s\n", errbuf);
        return (-1);
    }
    cur_iface.pcap_handler = tmp_handler;
    strncpy(cur_iface.dev_name, dev, IFNAMSIZ);
    return (0);
}
