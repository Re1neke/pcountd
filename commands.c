#include <sniffer.h>

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
    remove(PID_FILE);
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
    uint8_t ip[4];
    int read;
    // const memstor_t *test;
    // ipstat_t test1;

    if (argc != 3 || strcmp(argv[2], "count")) {
         fprintf(stderr, "Wrong syntax. See help message for more information.\n");
         return ;
    }
    read = sscanf(argv[1], "%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]);
    if (read != 4) {
        fprintf(stderr, "Wrong ip address format.\n");
        return ;
    }
    // printf("%x\n", *((uint32_t *)ip));
    // test = get_from_storage(*((uint32_t *)ip));
    // if (test) {
    //     ;
        // printf("%zu", memstor_t->);
    // }
}

static void sniff_select(int argc, char *argv[])
{
    int change;

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
    else if (argc == 2) {
        ;
    }
    else
        ;
}

static void sniff_help(int argc, char *argv[])
{
    printf("Supported commands:\n");
    printf("\tstart  - packets are being sniffed from now on from default iface\n");
    printf("\tstop   - packets are not sniffed\n");
    printf("\tshow [ip] count       - print number of packets received from ip address\n");
    printf("\tselect iface [iface]  - select interface for sniffing\n");
    printf("\tstat [iface]  - show all collected statistics for particular interface,\n");
    printf("\t                if ifaceomitted - for all interfaces.\n");
    printf("\t--help        - show this message\n");
}

void select_command(int argc, char *argv[])
{
    const uint8_t com_count = 6;
    const char *command[] = {
        "start",
        "stop",
        "show",
        "select",
        "stat",
        "--help"
    };
    const comfunc_t command_handler[] = {
        &sniff_start,
        &sniff_stop,
        &sniff_show,
        &sniff_select,
        &sniff_stat,
        &sniff_help,
    };

    for (int i = 0; i < com_count; i++) {
        if (!strcmp(command[i], argv[0])) {
            command_handler[i](argc, &argv[0]);
            return ;
        }
    }
    fprintf(stderr, "Command \"%s\" is not found.\n", argv[0]);
}
