#include <sniffer.h>

extern bool is_cli;

static void sniff_start(int argc, char *argv[])
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
    sniff_iface();
    remove_files();
}

static void sniff_stop(int argc, char *argv[])
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

static void sniff_show(int argc, char *argv[])
{
    uint32_t ip;

    if (argc != 3 || strcmp(argv[2], "count")) {
         fprintf(stderr, "Wrong syntax. See help message for more information.\n");
         return ;
    }
    ip = ipstrtoi(argv[1]);
    if (ip == 0) {
        fprintf(stderr, "Wrong ip address format.\n");
        return ;
    }
    if (!print_ipcount(ip))
        printf("No statistics for ip %s was found.\n", itoipstr(&ip));
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
    if (argc > 2) {
        fprintf(stderr, "Wrong syntax. See help message for more information.\n");
        return ;
    }
    else if (argc == 2)
        print_ifacestat(argv[1]);
    else
        print_allifacestat();
}

static void sniff_exit(int argc, char *argv[])
{
    if (is_cli == false)
        fprintf(stderr, "Command \"%s\" is not found.\n", argv[0]);
    free_memstor();
    exit(EXIT_SUCCESS);
}

static void sniff_help(int argc, char *argv[])
{
    printf("Supported commands:\n");
    printf("\tstart  - packets are being sniffed from now on from default iface\n");
    printf("\tstop   - packets are not sniffed\n");
    printf("\tshow [ip] count       - print number of packets received from ip address\n");
    if (is_cli == true)
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
