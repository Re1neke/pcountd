#include <sniffer.h>

static if_list_t *new_iflist(statlist_t *stat)
{
    if_list_t *new_list;
    statlist_t *copy;

    new_list = (if_list_t *)malloc(sizeof(if_list_t));
    if (new_list == NULL)
        return (NULL);
    copy = copy_stat(stat);
    if (copy == NULL) {
        free(new_list);
        return (NULL);
    }
    new_list->stats = copy;
    new_list->count = 1;
    new_list->next = NULL;
    return (new_list);
}

static uint32_t push_to_iflist(if_list_t **list, statlist_t *stat)
{
    if_list_t *cur;

    if (*list == NULL) {
        *list = new_iflist(stat);
        return (1);
    }
    cur = *list;
    while (strcmp(cur->stats->stat.iface, stat->stat.iface)) {
        if (cur->next == NULL)
            break ;
        cur = cur->next;
    }
    if (!strcmp(cur->stats->stat.iface, stat->stat.iface)) {
        append_to_statlist(&cur->stats, &stat->stat, stat->pos);
        cur->count++;
        return (0);
    }
    else {
        cur->next = new_iflist(stat);
        return (1);
    }
}

static uint32_t add_iface(if_list_t **list, statlist_t *stats, char *dev)
{
    statlist_t *ifstat;
    uint32_t count = 0;

    if (dev != NULL) {
        ifstat = get_if_stat(stats, dev);
        if (ifstat != NULL)
            count += push_to_iflist(list, ifstat);
    }
    else {
        while (stats != NULL) {
            count += push_to_iflist(list, stats);
            stats = stats->next;
        }
    }
    return (count);
}

uint32_t collect_iface_stat(stortree_t *root, if_list_t **list, char *dev)
{
    uint32_t count = 0;

    if (root == NULL)
        return (count);
    count += collect_iface_stat(root->left, list, dev);
    count += add_iface(list, root->stats, dev);
    count += collect_iface_stat(root->right, list, dev);
    return (count);   
}

uint32_t get_iface_stat(char *dev, if_list_t **list)
{
    extern stortree_t *storage;

    return (collect_iface_stat(storage, list, dev));
}

void free_iflist(if_list_t **iflist)
{
    if_list_t *cur, *tmp;

    cur = *iflist;
    while (cur != NULL) {
        free_statlist(&cur->stats);
        tmp = cur;
        cur = cur->next;
        free(tmp);
    }
    *iflist = NULL;
}
