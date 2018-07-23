#include <sniffer.h>

extern bool is_cli;

static void sniff_run(int argc, char *argv[])
{
    pid_t pid;

    if (read_pidfile() > 0) {
        fprintf(stderr, "The daemon is already running. Error.\n");
        return ;
    }
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Can not create daemon process. Error.\n");
        return ;
    }
    else if (pid > 0) {
        printf("Sniffing daemon is started with PID [%d]\n", (int)pid);
        return ;
    }
    prepare_daemon();
    if (create_pidfile(getpid()))
        exit(EXIT_FAILURE);
    start_daemon();
    remove_files();
    exit(EXIT_FAILURE);
}

static void sniff_halt(int argc, char *argv[])
{
    pid_t pid;

    pid = read_pidfile();
    if (pid <= 0) {
        fprintf(stderr, "The daemon is not running. Error.\n");
        return ;
    }
    if (kill(pid, SIGTERM) == -1)
        fprintf(stderr, "Can not stop the daemon. Error.\n");
    else
        printf("The daemon is successfuly stoped.\n");
}

static void sniff_start(int argc, char *argv[])
{
    int sock;
    const uint8_t com_id = (uint8_t)START;
    int8_t status;

    sock = open_cli_sock();
    if (sock < 0) {
        fprintf(stderr, "Can not connect to daemon. Error.\n");
        return ;      
    }
    send(sock, (void *)&com_id, sizeof(uint8_t), 0);
    recv(sock, (void *)&status, sizeof(int8_t), 0);
    if (status == 1)
        printf("Daemon is already sniffing.\n");
    else if (status == 0)
        printf("Daemon starts sniffing.\n");
    close(sock);
}

static void sniff_stop(int argc, char *argv[])
{
    int sock;
    const uint8_t com_id = (uint8_t)STOP;
    int8_t status;

    sock = open_cli_sock();
    if (sock < 0) {
        fprintf(stderr, "Can not connect to daemon. Error.\n");
        return ;      
    }
    send(sock, (void *)&com_id, sizeof(uint8_t), 0);
    recv(sock, (void *)&status, sizeof(int8_t), 0);
    if (status == 1)
        printf("Daemon is already stoped.\n");
    else if (status == 0)
        printf("Daemon stoped sniffing.\n");
    close(sock);
}

static void sniff_show(int argc, char *argv[])
{
    uint32_t ip, count;
    statlist_t *ip_list = NULL;
    ipstat_t tmp_stat;
    const uint8_t com_id = (uint8_t)SHOW_CNT;
    int sock;

    if (argc != 3 || strcmp(argv[2], "count")) {
         fprintf(stderr, "Wrong syntax. See help message for more information.\n");
         return ;
    }
    ip = ipstrtoi(argv[1]);
    if (ip == 0) {
        fprintf(stderr, "Wrong ip address format.\n");
        return ;
    }
    sock = open_cli_sock();
    if (sock < 0) {
        fprintf(stderr, "Can not connect to daemon. Error.\n");
        return ;      
    }
    send(sock, (void *)&com_id, sizeof(uint8_t), 0);
    send(sock, (void *)&ip, sizeof(uint32_t), 0);
    recv(sock, (void *)&count, sizeof(uint32_t), 0);
    for (uint32_t i = 0; i < count; i++) {
        memset(&tmp_stat, 0, sizeof(ipstat_t));
        recv(sock, (void *)&tmp_stat, sizeof(ipstat_t), 0);
        append_to_statlist(&ip_list, &tmp_stat, 0);
    }
    print_ipcount(ip_list);
    free_statlist(&ip_list);
    close(sock);
}

static void sniff_select(int argc, char *argv[])
{
    int sock;
    int8_t change;
    const uint8_t com_id = (uint8_t)SELECT;

    if (argc != 3 || strcmp(argv[1], "iface")) {
        fprintf(stderr, "Wrong syntax. See help message for more information.\n");
        return ;
    }
    sock = open_cli_sock();
    if (sock < 0) {
        fprintf(stderr, "Can not connect to daemon. Error.\n");
        return ;      
    } 
    send(sock, (void *)&com_id, sizeof(uint8_t), 0);
    send(sock, (void *)argv[2], IFNAMSIZ, 0);
    recv(sock, (void *)&change, sizeof(int8_t), 0);
    if (change == 0)
        printf("Device successfuly changed. Restart sniffer for start sniffing.\n");
    else if (change == 1)
        fprintf(stderr, "Wrong device name.\n");
    close(sock);
}

static void sniff_stat(int argc, char *argv[])
{
    uint32_t if_count;
    if_list_t *list = NULL, *cur_if;
    ipstat_t tmp_stat;
    const uint8_t com_id = (argc == 2) ? (uint8_t)STAT : (uint8_t)STAT_ALL;
    int sock;

    if (argc > 2) {
        fprintf(stderr, "Wrong syntax. See help message for more information.\n");
        return ;
    }
    sock = open_cli_sock();
    send(sock, (void *)&com_id, sizeof(uint8_t), 0);
    if (sock < 0) {
        fprintf(stderr, "Can not connect to daemon. Error.\n");
        return ;      
    }
    if (argc == 2)
        send(sock, (void *)argv[1], IFNAMSIZ, 0);
    recv(sock, (void *)&if_count, sizeof(uint32_t), 0);
    for (uint32_t i = 0; i < if_count; i++) {
        cur_if = new_empty_iflist();
        if (cur_if == NULL)
            break ;
        recv(sock, (void *)&cur_if->count, sizeof(uint32_t), 0);
        for (uint32_t j = 0; j < cur_if->count; j++) {
            memset(&tmp_stat, 0, sizeof(ipstat_t));
            recv(sock, (void *)&tmp_stat, sizeof(ipstat_t), 0);
            append_to_statlist(&cur_if->stats, &tmp_stat, 0);
        }
        push_to_iflist(&list, cur_if);
    }
    print_ifacestat(list);
    free_iflist(&list);
    close(sock);
}

static void sniff_exit(int argc, char *argv[])
{
    if (is_cli == false)
        fprintf(stderr, "Command \"%s\" is not found.\n", argv[0]);
    exit(EXIT_SUCCESS);
}

static void sniff_help(int argc, char *argv[])
{
    printf("Supported commands:\n");
    printf("\trun    - sniffing daemon is started and waits for next commands\n");
    printf("\thalt   - kill the daemon process\n");
    printf("\tstart  - packets are being sniffed from now on from default iface\n");
    printf("\tstop   - packets are not sniffed\n");
    printf("\tshow [ip] count       - print number of packets received from ip address\n");
        printf("\tselect iface [iface]  - select interface for sniffing\n");
    printf("\tstat [iface]  - show all collected statistics for particular interface,\n");
    printf("\t                if ifaceomitted - for all interfaces.\n");
    if (is_cli == true)
        printf("\texit          - exit from cli\n");
    printf("\t--help        - show this message\n");
}

void select_command(int argc, char *argv[])
{
    const command_t command[] = {
        {"run", &sniff_run},
        {"halt", &sniff_halt},
        {"start", &sniff_start},
        {"stop", &sniff_stop},
        {"show", &sniff_show},
        {"select", &sniff_select},
        {"stat", &sniff_stat},
        {"exit", &sniff_exit},
        {"--help", &sniff_help}
    };
    const uint8_t com_count = sizeof(command) / sizeof(command_t);

    for (uint8_t i = 0; i < com_count; i++) {
        if (!strcmp(command[i].name, argv[0])) {
            command[i].func(argc, &argv[0]);
            return ;
        }
    }
    fprintf(stderr, "Command \"%s\" is not found.\n", argv[0]);
}
