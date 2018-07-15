#include <sniffer.h>

memstor_t *storage = NULL;
uint32_t stor_size = 0;
uint32_t stor_full = 0;

memstor_t *new_memstor(void)
{
    memstor_t *new_stor;

    new_stor = (memstor_t *)malloc(DEFAULT_STORAGE * sizeof(memstor_t));
    if (new_stor != NULL) {
        storage = new_stor;
        stor_size = DEFAULT_STORAGE;
    }
    return (new_stor);
}

memstor_t *expand_memstor(void)
{
    memstor_t *new_stor;
    uint32_t new_size;

    if (stor_size * 2 > UINT32_MAX)
        new_size = UINT32_MAX;
    else
        new_size = stor_size * 2;
    new_stor = (memstor_t *)malloc(new_size * sizeof(memstor_t));
    if (new_stor == NULL)
        return (NULL);
    memset(new_stor, 0, new_size);
    memcpy(new_stor, storage, stor_size);
    free(storage);
    storage = new_stor;
    stor_size = new_size;
    return (new_stor);
}

int add_to_memstor(uint32_t file_pos, ipstat_t *stat)
{
    uint32_t i, j;

    if (stor_full + 1 > stor_size) {
        if (!expand_memstor())
            return (-1);
    }
    for (i = 0; i < stor_full; i++) {
        if (storage[i].stat.ip_addr > stat->ip_addr)
            break ;
    }
    for (j = stor_full; j > i; j--)
        storage[j] = storage[j - 1];
    // if (iface != NULL)
    //     strncpy(storage[i].stat.iface, iface, IFNAMSIZ);
    // storage[i].stat.ip_addr = ip_addr;
    // storage[i].stat.packet_count = packets;
    storage[i].stat = *stat;
    storage[i].pos = file_pos;
    stor_full++;
    return (0);
}

memstor_t *get_from_memstor(uint32_t ip_addr)
{
    uint32_t max, min, n;

    if (stor_full == 0)
        return (NULL);
    max = stor_full;
    min = 0;
    n = (min + max) / 2;
    while (ip_addr != storage[n].stat.ip_addr) {
        if (max == min + 1)
            return (NULL);
        if (ip_addr < storage[n].stat.ip_addr)
            max = n;
        else if (ip_addr > storage[n].stat.ip_addr)
            min = n;
        n = (min + max) / 2; 
    }
    return (&storage[n]);
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
    // ipstat_t cur_stat;

    stor_file = fopen(STORAGE_FILE, "r+b");
    // fseek(stor_file, pos, SEEK_SET);
    // fread(&cur_stat, sizeof(ipstat_t), 1, stor_file);
    fseek(stor_file, file_pos, SEEK_SET);
    fwrite(stat, sizeof(ipstat_t), 1, stor_file);
    fclose(stor_file);
    return (0);
}

// int incr_value(uint32_t pos)
// {
//     FILE *stor_file;
//     ipstat_t ip_struct;

//     stor_file = fopen(STORAGE_FILE, "r+b");
//     fseek(stor_file, pos, SEEK_SET);
//     fread(&ip_struct, sizeof(ipstat_t), 1, stor_file);
//     fseek(stor_file, pos, SEEK_SET);
//     ip_struct.packet_count++;
//     fwrite(&ip_struct, sizeof(ipstat_t), 1, stor_file);
//     fclose(stor_file);
//     return (0);
// }

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
