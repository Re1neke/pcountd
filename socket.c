#include <sniffer.h>

extern pthread_mutex_t mutex;

int open_srv_sock(void)
{
    int ssock_fd;
    struct sockaddr_un addr;

    unlink(SOCK_FILE);
    ssock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ssock_fd < 0)
        return (ssock_fd);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_FILE, sizeof(addr.sun_path));
    if(bind(ssock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return (-1);
    return (ssock_fd);
}

int open_cli_sock(void)
{
    int csock_fd;
    struct sockaddr_un addr;

    csock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (csock_fd < 0)
        return (-1);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCK_FILE);
    if(connect(csock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return (-1);
    return (csock_fd);
}

static void sniff_start(int csock_fd, uint8_t com_id)
{
    int8_t status;
    extern iface_t cur_iface;

    if (cur_iface.sniff)
        status = 1;
    else
        status = (int8_t)set_iface();
    send(csock_fd, (void *)&status, sizeof(int8_t), 0);
}

static void sniff_stop(int csock_fd, uint8_t com_id)
{
    int8_t status;
    extern iface_t cur_iface;

    if (!cur_iface.sniff)
        status = 1;
    else
        status = (int8_t)unset_iface();
    send(csock_fd, (void *)&status, sizeof(int8_t), 0);
}

static void sniff_select(int csock_fd, uint8_t com_id)
{
    uint8_t buf[IFNAMSIZ + 1];
    int8_t change;

    memset(buf, 0, IFNAMSIZ + 1);
    recv(csock_fd, (void *)buf, IFNAMSIZ, 0);
    change = (int8_t)select_iface((char *)buf);
    send(csock_fd, (void *)&change, sizeof(int8_t), 0);
}

static void sniff_show(int csock_fd, uint8_t com_id)
{
    statlist_t *cur_chain, *ip_list = NULL;
    uint32_t ip, count;

    recv(csock_fd, (void *)&ip, sizeof(uint32_t), 0);
    pthread_mutex_lock(&mutex);
    count = get_ip_stat(ip, &ip_list);
    pthread_mutex_unlock(&mutex);
    send(csock_fd, (void *)&count, sizeof(uint32_t), 0);
    cur_chain = ip_list;
    while (cur_chain != NULL) {
        send(csock_fd, (void *)&cur_chain->stat, sizeof(ipstat_t), 0);
        cur_chain = cur_chain->next;
    }
    free_statlist(&ip_list);
}

static void sniff_stat(int csock_fd, uint8_t com_id)
{
    statlist_t *cur_ip;
    if_list_t *cur_if, *if_list = NULL;
    uint32_t count_if;
    uint8_t buf[IFNAMSIZ + 1];

    memset(buf, 0, IFNAMSIZ + 1);
    if (com_id == STAT)
        recv(csock_fd, (void *)buf, IFNAMSIZ, 0);
    pthread_mutex_lock(&mutex);
    count_if = get_if_stat((com_id == STAT) ? (char *)buf : NULL, &if_list);
    pthread_mutex_unlock(&mutex);
    send(csock_fd, (void *)&count_if, sizeof(uint32_t), 0);
    cur_if = if_list;
    while (cur_if != NULL) {
        send(csock_fd, (void *)&cur_if->count, sizeof(uint32_t), 0);
        cur_ip = cur_if->stats;
        while (cur_ip != NULL) {
            send(csock_fd, (void *)&cur_ip->stat, sizeof(ipstat_t), 0);
            cur_ip = cur_ip->next;
        }
        cur_if = cur_if->next;
    }
    free_iflist(&if_list);
}

static void handle_request(int csock_fd, uint8_t com_id)
{
    const scommand_t command[] = {
        {START, &sniff_start},
        {STOP, &sniff_stop},
        {SHOW_CNT, &sniff_show},
        {SELECT, &sniff_select},
        {STAT, &sniff_stat},
        {STAT_ALL, &sniff_stat}
    };
    const uint8_t com_count = sizeof(command) / sizeof(scommand_t);

    for (uint8_t i = 0; i < com_count; i++) {
        if (command[i].com_id == com_id) {
            command[i].func(csock_fd, com_id);
            return ;
        }
    }
}

void start_listen(int ssock_fd)
{
    int csock_fd;
    ssize_t b_read;
    uint8_t com_id;

    listen(ssock_fd, 1);
    while (true) {
        csock_fd = accept(ssock_fd, NULL, NULL);
        if (csock_fd < 0)
            continue ;
        while (true) {
            b_read = recv(csock_fd, (void *)&com_id, sizeof(uint8_t), 0);
            if(b_read <= 0)
                break;
            handle_request(csock_fd, com_id);
        }
        close(csock_fd);
    }
    close(ssock_fd);
}
