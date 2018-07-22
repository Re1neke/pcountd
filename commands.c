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
    set_iface(NULL);
    file_to_memory();
    // sniff_iface();
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

}

static void sniff_stop(int argc, char *argv[])
{

}

static void sniff_show(int argc, char *argv[])
{
    uint32_t ip;
    statlist_t *ip_list = NULL;

    if (argc != 3 || strcmp(argv[2], "count")) {
         fprintf(stderr, "Wrong syntax. See help message for more information.\n");
         return ;
    }
    ip = ipstrtoi(argv[1]);
    if (ip == 0) {
        fprintf(stderr, "Wrong ip address format.\n");
        return ;
    }
    get_ip_stat(ip, &ip_list);
    print_ipcount(ip_list);
    free_statlist(&ip_list);
}

static void sniff_select(int argc, char *argv[])
{
    int change;

    if (is_cli == false) {
        fprintf(stderr, "Command \"%s\" is not found.\n", argv[0]);
        return ;
    }
    if (argc != 3 || strcmp(argv[1], "iface")) {
         fprintf(stderr, "Wrong syntax. See help message for more information.\n");
         return ;
    }
    change = change_iface(argv[2]);
    if (change == 0)
        printf("Device successfuly changed. Restart daemon for start sniffing.\n");
    else if (change == 1)
        fprintf(stderr, "Wrong device name.\n");
}

static void sniff_stat(int argc, char *argv[])
{
    if_list_t *list = NULL;

    if (argc > 2) {
        fprintf(stderr, "Wrong syntax. See help message for more information.\n");
        return ;
    }
    get_iface_stat((argc == 2) ? argv[1] : NULL, &list);
    print_ifacestat(list);
    free_iflist(&list);
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
    printf("\t#show [ip] count       - print number of packets received from ip address\n");
    if (is_cli == true)
        printf("\t#select iface [iface]  - select interface for sniffing\n");
    printf("\t#stat [iface]  - show all collected statistics for particular interface,\n");
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

    for (int i = 0; i < com_count; i++) {
        if (!strcmp(command[i].name, argv[0])) {
            command[i].func(argc, &argv[0]);
            return ;
        }
    }
    fprintf(stderr, "Command \"%s\" is not found.\n", argv[0]);
}
