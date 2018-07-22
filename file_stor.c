#include <sniffer.h>

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
    stortree_t *stor_node;

    stor_file = fopen(STORAGE_FILE, "rb");
    if (stor_file == NULL)
        return (-1);
    pos = (uint32_t)ftell(stor_file);
    while (fread(&ip_stat, sizeof(ipstat_t), 1, stor_file) > 0) {
        stor_node = get_stor_node(ip_stat.ip_addr);
        if (stor_node != NULL)
            append_to_statlist(&stor_node->stats, &ip_stat, pos);
        else
            add_node_to_storage(&ip_stat, pos);
        pos = (uint32_t)ftell(stor_file);
    }
    fclose(stor_file);
    return (0);
}
