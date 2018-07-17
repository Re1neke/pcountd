#include <sniffer.h>

memstor_t **storage = NULL;
uint32_t stor_size = 0;
uint32_t stor_full = 0;

memstor_t **new_memstor(size_t size)
{
    memstor_t **new_stor;

    new_stor = (memstor_t **)malloc(DEFAULT_STORAGE * sizeof(memstor_t *));
    if (new_stor != NULL) {
        storage = new_stor;
        stor_size = DEFAULT_STORAGE;
    }
    return (new_stor);
}

memstor_t **expand_memstor(void)
{
    memstor_t **new_stor;
    uint32_t new_size;

    if (stor_size * 2 > UINT32_MAX)
        new_size = UINT32_MAX;
    else
        new_size = stor_size * 2;
    new_stor = (memstor_t **)malloc(new_size * sizeof(memstor_t *));
    if (new_stor == NULL)
        return (NULL);
    memset(new_stor, 0, new_size * sizeof(memstor_t *));
    memcpy(new_stor, storage, stor_size);
    free(storage);
    storage = new_stor;
    stor_size = new_size;
    return (new_stor);
}

void free_memstorchain(memstor_t *chain)
{
    memstor_t *tmp_ptr;

    while (chain != NULL) {
        tmp_ptr = chain;
        chain = chain->next;
        free(tmp_ptr);
    }
}

void free_memstor(void)
{
    if (storage == NULL)
        return ;
    for (uint32_t i = 0; i < stor_full; i++)
        free_memstorchain(storage[i]);
    free(storage);
    storage = NULL;
    stor_size = 0;
    stor_full = 0;
}

static memstor_t *create_chain(uint32_t file_pos, const ipstat_t *stat)
{
    memstor_t *new_val;

    new_val = (memstor_t *)malloc(sizeof(memstor_t));
    if (new_val == NULL)
        return (NULL);
    new_val->stat = *stat;
    new_val->pos = file_pos;
    new_val->next = NULL;
    return (new_val);
}

static int push_to_pos(uint32_t stor_pos, uint32_t file_pos, ipstat_t *stat)
{
    memstor_t *new_val;

    if (stor_full + 1 > stor_size) {
        if (!expand_memstor())
            return (-1);
    }
    new_val = create_chain(file_pos, stat);
    if (new_val == NULL)
        return (-1);
    for (uint32_t j = stor_full; j > stor_pos; j--)
        storage[j] = storage[j - 1];
    storage[stor_pos] = new_val;
    stor_full++;
    return (0);
}

static int add_chain(memstor_t **ip_chain, uint32_t file_pos, const ipstat_t *stat)
{
    memstor_t *new_val, *tmp_p;

    new_val = create_chain(file_pos, stat);
    if (new_val == NULL)
        return (-1);
    if (*ip_chain == NULL) {
        *ip_chain = new_val;
        return (0);
    }
    tmp_p = *ip_chain;
    while (tmp_p->next != NULL)
        tmp_p = tmp_p->next;
    tmp_p->next = new_val;
    return (0);
}

int add_to_memstor(uint32_t file_pos, ipstat_t *stat)
{
    uint32_t max, min, n;

    if (stor_full == 0)
        return (push_to_pos(0, file_pos, stat));
    max = stor_full;
    min = 0;
    n = (min + max) / 2;
    while (stat->ip_addr != storage[n]->stat.ip_addr) {
        if (max == min + 1) {
            if (stat->ip_addr > storage[min]->stat.ip_addr)
                return (push_to_pos(max,file_pos, stat));
            else
                return (push_to_pos(min,file_pos, stat));
        }
        if (stat->ip_addr < storage[n]->stat.ip_addr)
            max = n;
        else if (stat->ip_addr > storage[n]->stat.ip_addr)
            min = n;
        n = (min + max) / 2;
    }
    return (add_chain(&storage[n], file_pos, stat));
}

static const memstor_t *get_iface_from_chain(const memstor_t *chain, char *dev)
{
    while (chain != NULL) {
        if (!strcmp(chain->stat.iface, dev))
            break ;
        chain = chain->next;
    }
    return (chain);
}

static if_list_t *new_iface_stat(const memstor_t *pushd_stat)
{
    if_list_t *new_chain;

    new_chain = (if_list_t *)malloc(sizeof(if_list_t));
    if (new_chain == NULL)
        return (NULL);
    new_chain->list = NULL;
    new_chain->next = NULL;
    if (add_chain(&new_chain->list, pushd_stat->pos, &pushd_stat->stat) == -1) {
        free(new_chain);
        return (NULL);
    }
    return (new_chain);
}

static int push_to_ifacelist(if_list_t **if_list, const memstor_t *pushd_stat)
{
    if_list_t *tmp_list;

    if (*if_list == NULL) {
        *if_list = new_iface_stat(pushd_stat);
        return ((*if_list == NULL) ? -1 : 0);
    }
    tmp_list = *if_list;
    while (tmp_list != NULL) {
        if (!strcmp(tmp_list->list->stat.iface, pushd_stat->stat.iface)) {
            return (add_chain(&tmp_list->list, pushd_stat->pos, &pushd_stat->stat));
        }
        if (tmp_list->next == NULL)
            break ;
        tmp_list = tmp_list->next;
    }
    tmp_list->next = new_iface_stat(pushd_stat);
    return ((tmp_list->next == NULL) ? -1 : 0);
}

if_list_t *get_iface_sorted_list(void)
{
    if_list_t *iface_list = NULL;
    const memstor_t *cur_stor;

    for (int i = 0; i < stor_full; i++) {
        cur_stor = storage[i];
        while (cur_stor != NULL) {
            push_to_ifacelist(&iface_list, cur_stor);
            cur_stor = cur_stor->next;
        }
    }
    return (iface_list);
} 

memstor_t *get_iface_from_memstor(char *dev)
{
    memstor_t *iface_list, *list_tail, *new_chain;
    const memstor_t *cur_iface;

    iface_list = list_tail = NULL;
    for (int i = 0; i < stor_full; i++) {
        cur_iface = get_iface_from_chain(storage[i], dev);
        if (cur_iface == NULL)
            continue ;
        new_chain = create_chain(cur_iface->pos, &cur_iface->stat);
        if (new_chain == NULL) {
            free_memstorchain(iface_list);
            return (NULL);
        }
        if (iface_list == NULL || list_tail == NULL)
            iface_list = list_tail = new_chain;
        else {
            list_tail->next = new_chain;
            list_tail = list_tail->next;
        }
    }
    return (iface_list);
}

const memstor_t *get_from_memstor(uint32_t ip_addr, char *dev)
{
    const memstor_t *search_ip;

    search_ip = get_ip_from_memstor(ip_addr);
    return (get_iface_from_chain(search_ip, dev));
}

const memstor_t *get_ip_from_memstor(uint32_t ip_addr)
{
    uint32_t max, min, n;

    if (stor_full == 0)
        return (NULL);
    max = stor_full;
    min = 0;
    n = (min + max) / 2;
    while (ip_addr != storage[n]->stat.ip_addr) {
        if (max == min + 1)
            return (NULL);
        if (ip_addr < storage[n]->stat.ip_addr)
            max = n;
        else if (ip_addr > storage[n]->stat.ip_addr)
            min = n;
        n = (min + max) / 2; 
    }
    return (storage[n]);
}

int32_t write_to_file(ipstat_t *stat)
{
    FILE *stor_file;
    int32_t pos;

    stor_file = fopen(STORAGE_FILE, "ab");
    if (stor_file == NULL)
        return (-1);
    pos = (int32_t)ftell(stor_file);
    if (fwrite(stat, sizeof(ipstat_t), 1, stor_file) < 1) {
        fclose(stor_file);
        return (-1);
    }
    fclose(stor_file);
    return (pos);
}

int update_file(uint32_t file_pos, const ipstat_t *stat)
{
    FILE *stor_file;

    stor_file = fopen(STORAGE_FILE, "r+b");
    fseek(stor_file, file_pos, SEEK_SET);
    fwrite(stat, sizeof(ipstat_t), 1, stor_file);
    fclose(stor_file);
    return (0);
}

int file_to_memory(void)
{
    FILE *stor_file;
    ipstat_t ip_stat;
    uint32_t pos;

    stor_file = fopen(STORAGE_FILE, "rb");
    if (stor_file == NULL)
        return (-1);
    pos = (uint32_t)ftell(stor_file);
    while (fread(&ip_stat, sizeof(ipstat_t), 1, stor_file) > 0) {
        add_to_memstor(pos, &ip_stat);
        pos = (uint32_t)ftell(stor_file);
    }
    fclose(stor_file);
    return (0);
}

int reload_file(void)
{
    uint32_t cur_size;

    cur_size = stor_size;
    free_memstor();
    if (new_memstor(cur_size) == NULL)
        return (-1);
    return (file_to_memory());
}