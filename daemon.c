#include <sniffer.h>

pthread_mutex_t mutex;
pthread_t tid;

static void term_handler(int signum)
{
    unset_iface();
    pthread_cancel(tid);
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&mutex);
    free_storage();
    remove_files();
    exit(EXIT_SUCCESS);
}

int prepare_daemon(void)
{
    pid_t sid;

    signal(SIGTERM, &term_handler);
    signal(SIGINT, &term_handler);
    umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    sid = setsid();
    if (sid < 0)
        return (-1);
    if ((chdir("/")) < 0)
        return (-1);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    return (0);
}

void start_daemon(void)
{
    int ssock_fd;

    ssock_fd = open_srv_sock();
    if (ssock_fd < 0)
        return ;
    file_to_memory();
    if (pthread_mutex_init(&mutex, NULL))
        return ;
    if (pthread_create(&tid, NULL, &sniff_iface, NULL))
        return ;
    start_listen(ssock_fd);
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&mutex);
}

void remove_files(void)
{
    remove(SOCK_FILE);
    remove(PID_FILE);
    remove(RUN_DIR);
}

int create_pidfile(pid_t pid)
{
    FILE *pid_file;

    if (access(PID_FILE, F_OK) != -1)
        return (1);
    remove_files();
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
