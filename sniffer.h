#ifndef __SNIFFER_H
# define __SNIFFER_H 1

# include <sys/types.h>
# include <sys/stat.h>

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stdbool.h>
# include <string.h>
# include <limits.h>

# include <ctype.h>
# include <fcntl.h>
# include <errno.h>
# include <unistd.h>
# include <signal.h>

# include <pcap.h>
# include <linux/if_ether.h>
# include <linux/ip.h>
# include <arpa/inet.h>

# define PID_FILE "/var/run/pcountd.pid"
# define STORAGE_FILE "/var/lib/pcountd_storage.bin"

typedef void (*comfunc_t)(int argc, char *argv[]);

void select_command(int argc, char *argv[]);
void run_cli(void);

pid_t read_pidfile(void);
int create_pidfile(pid_t pid);
void prepare_daemon(void);

# define IFNAMSIZ 16

typedef struct {
    char iface[IFNAMSIZ + 1];
    uint32_t ip_addr;
    size_t packet_count;
} ipstat_t;

typedef struct {
    pcap_t *pcap_handler;
    char *dev_name;
} iface_t;

extern iface_t cur_iface;

void sniff_iface(void);
int change_iface(char *dev);
int set_iface(char *dev);

typedef struct {
    ipstat_t stat;
    uint32_t pos;
} memstor_t;

#define DEFAULT_STORAGE (uint32_t)64

memstor_t *new_memstor(void);
int file_to_memory(void);
memstor_t *get_from_memstor(uint32_t ip_addr);
int update_file(uint32_t file_pos, const ipstat_t *stat);
int32_t write_to_file(ipstat_t *stat);
int add_to_memstor(uint32_t file_pos, ipstat_t *stat);

#endif
