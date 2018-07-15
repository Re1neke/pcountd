#ifndef __SNIFFER_H
# define __SNIFFER_H 1

# include <sys/types.h>
# include <sys/stat.h>

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stdbool.h>
# include <string.h>

# include <ctype.h>
# include <fcntl.h>
# include <errno.h>
# include <unistd.h>
# include <signal.h>

# include <pcap.h>
# include <linux/if_ether.h>
# include <linux/ip.h>
# include <arpa/inet.h>

# define PID_FILE "/run/pcountd.pid"

typedef void (*comfunc_t)(int argc, char *argv[]);

void select_command(int argc, char *argv[]);
void run_cli(void);

pid_t read_pidfile(void);
int create_pidfile(pid_t pid);
void prepare_daemon(void);

typedef struct {
    pcap_t *pcap_handler;
    char *dev_name;
} iface_t;

extern iface_t cur_iface;

void sniff_iface(void);
int change_iface(char *dev);
int set_iface(char *dev);

#endif
