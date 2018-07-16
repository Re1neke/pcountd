#include <sniffer.h>

static void term_handler(int signum)
{
    if (cur_iface.pcap_handler != NULL) {
        pcap_breakloop(cur_iface.pcap_handler);
        pcap_close(cur_iface.pcap_handler);
    }
    free_memstor();
    remove_files();
    exit(EXIT_SUCCESS);
}

void prepare_daemon(void)
{
    pid_t sid;

    signal(SIGTERM, &term_handler);
    umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    sid = setsid();
    if (sid < 0) {
        remove_files();
        exit(EXIT_FAILURE);
    }
    if ((chdir("/")) < 0) {
        remove_files();
        exit(EXIT_FAILURE);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void remove_files(void)
{
    remove(PID_FILE);
    remove(RUN_DIR);
}

int create_pidfile(pid_t pid)
{
    FILE *pid_file;

    if (access(PID_FILE, F_OK) != -1)
        return (1);
    if (mkdir(RUN_DIR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1)
        return (-1);
    pid_file = fopen(PID_FILE, "w");
    if (pid_file == NULL)
        return (-1);
    fprintf(pid_file, "%d\n", (int)pid);
    fclose(pid_file);
    return (0);
}

pid_t read_pidfile(void)
{
    FILE *pid_file;
    char *pid_str = NULL;
    size_t pid_len = 0;
    pid_t pid = 0;

    if (access(PID_FILE, F_OK) == -1)
        return (-1);
    pid_file = fopen(PID_FILE, "r");
    if (pid_file == NULL)
        return (-1);
    getline(&pid_str, &pid_len, pid_file);
    if (pid_str != NULL) {
        pid = (pid_t)atoi(pid_str);
        free(pid_str);
    }
    fclose(pid_file);
    return (pid);
}
