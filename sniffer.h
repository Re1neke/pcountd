#ifndef __SNIFFER_H
# define __SNIFFER_H 1

# include <sys/types.h>
# include <sys/stat.h>
# include <sys/socket.h>
# include <sys/un.h>

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
# include <net/if.h>
# include <arpa/inet.h>

# define RUN_DIR "/var/run/pcountd"
# define PID_FILE RUN_DIR "/pcountd.pid"
# define SOCK_FILE RUN_DIR "/pcountd.sock"
# define STORAGE_FILE "/var/lib/pcountd.storage"


typedef void (*comfunc_t)(int argc, char *argv[]);

typedef struct {
    char *name;
    comfunc_t func;
} command_t;

void select_command(int argc, char *argv[]);
void run_cli(void);


void remove_files(void);
pid_t read_pidfile(void);
int create_pidfile(pid_t pid);
void prepare_daemon(void);


typedef struct {
    pcap_t *pcap_handler;
    char dev_name[IFNAMSIZ + 1];
} iface_t;


void sniff_iface(void);
int change_iface(char *dev);
int set_iface(char *dev);


typedef struct {
    char iface[IFNAMSIZ + 1];
    uint32_t ip_addr;
    size_t packet_count;
} ipstat_t;

typedef struct stortree_s {
    storinfo_t *stats;
    uint32_t pos;
    bool is_black;
    struct stortree_s *parent;
    struct stortree_s *left;
    struct stortree_s *right;
} stortree_t;

typedef struct statlist_s {
    ipstat_t stat;
    struct statlist_s *next;
} statlist_t;

stortree_t *add_to_storage(ipstat_t *stat, uint32_t file_pos);
stortree_t *get_first_node(uint32_t ip_addr);
stortree_t *get_stor_node(uint32_t ip_addr, char *dev);
void free_storage(void);

int get_ip_stat(uint32_t ip_addr, statlist_t **list);
void free_statlist(statlist_t **list);


int32_t write_to_file(ipstat_t *stat);
int update_file(uint32_t file_pos, const ipstat_t *stat);
int file_to_memory(void);


char *itoipstr(const uint32_t *ip);
uint32_t ipstrtoi(const char *ipstr);
void print_ipcount(statlist_t *ip_list);
// int print_ifacestat(char *iface_name);
// int print_allifacestat(void);

#endif
