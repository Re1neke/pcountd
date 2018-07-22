#include <sniffer.h>



// if_list_t *get_iface_sorted_list(void)
// {
//     if_list_t *iface_list = NULL;
//     const memstor_t *cur_stor;

//     for (int i = 0; i < stor_full; i++) {
//         cur_stor = storage[i];
//         while (cur_stor != NULL) {
//             push_to_ifacelist(&iface_list, cur_stor);
//             cur_stor = cur_stor->next;
//         }
//     }
//     return (iface_list);
// } 

// memstor_t *get_iface_from_memstor(char *dev)
// {
//     memstor_t *iface_list, *list_tail, *new_chain;
//     const memstor_t *cur_iface;

//     iface_list = list_tail = NULL;
//     for (int i = 0; i < stor_full; i++) {
//         cur_iface = get_iface_from_chain(storage[i], dev);
//         if (cur_iface == NULL)
//             continue ;
//         new_chain = create_chain(cur_iface->pos, &cur_iface->stat);
//         if (new_chain == NULL) {
//             free_memstorchain(iface_list);
//             return (NULL);
//         }
//         if (iface_list == NULL || list_tail == NULL)
//             iface_list = list_tail = new_chain;
//         else {
//             list_tail->next = new_chain;
//             list_tail = list_tail->next;
//         }
//     }
//     return (iface_list);
// }


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
        add_to_storage(&ip_stat, pos);
        pos = (uint32_t)ftell(stor_file);
    }
    fclose(stor_file);
    return (0);
}

// int reload_file(void)
// {
//     uint32_t cur_size;

//     cur_size = stor_size;
//     free_memstor();
//     if (new_memstor(cur_size) == NULL)
//         return (-1);
//     return (file_to_memory());
// }