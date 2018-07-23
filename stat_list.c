#include <sniffer.h>

static statlist_t *new_stat(ipstat_t *stat, uint32_t pos)
{
    statlist_t *new;

    new = (statlist_t *)malloc(sizeof(statlist_t));
    if (new == NULL)
        return (NULL);
    new->stat = *stat;
    new->pos = pos;
    new->next = NULL;
    return (new);
}

statlist_t *copy_stat(statlist_t *chain)
{
    statlist_t *new_chain;

    new_chain = (statlist_t *)malloc(sizeof(statlist_t));
    if (new_chain == NULL)
        return (NULL);
    new_chain->stat = chain->stat;
    new_chain->pos = chain->pos;
    new_chain->next = NULL;
    return (new_chain);
}

static statlist_t *push_to_statlist(statlist_t **head, statlist_t *chain)
{
    statlist_t *tmp;

    if (*head == NULL) {
        *head = chain;
        return (chain);
    }
    tmp = *head;
    while (tmp->next != NULL)
        tmp = tmp->next;
    tmp->next = chain;
    return (chain);
}

statlist_t *append_to_statlist(statlist_t **head, ipstat_t *stat, uint32_t pos)
{
    statlist_t *new_chain;

    new_chain = new_stat(stat, pos);
    if (new_chain == NULL)
        return (NULL);
    push_to_statlist(head, new_chain);
    return (new_chain);
}

statlist_t *get_iface(statlist_t *statlist, char *dev)
{
    while (statlist != NULL) {
        if (!strcmp(statlist->stat.iface, dev))
            return (statlist);
        statlist = statlist->next;
    }
    return (NULL);
}

uint32_t get_ip_stat(uint32_t ip_addr, statlist_t **list)
{
    statlist_t *chain, *copy;
    stortree_t *ip_node;
    uint32_t count = 0;

    ip_node = get_stor_node(ip_addr);
    if (ip_node == NULL)
        return (0);
    chain = ip_node->stats;
    while (chain != NULL) {
        copy = copy_stat(chain);
        if (copy != NULL) {
            push_to_statlist(list, copy);
            count++;
        }
        chain = chain->next;
    }
    return (count);
}

void free_statlist(statlist_t **list)
{
    statlist_t *chain, *tmp;

    chain  = *list;
    while (chain != NULL) {
        tmp = chain;
        chain = chain->next;
        free(tmp);
    }
    *list = NULL;
}
