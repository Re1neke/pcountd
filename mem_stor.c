#include <sniffer.h>

stortree_t *storage = NULL;

static stortree_t *new_node(ipstat_t *ipstat, uint32_t pos)
{
    stortree_t *node;

    node = (stortree_t *)malloc(sizeof(stortree_t));
    if (node == NULL)
        return (NULL);
    node->stat = *ipstat;
    node->pos = pos;
    node->is_black = false;
    node->parent = NULL;
    node->left = NULL;
    node->right = NULL;
    return (node);
}

static stortree_t *push_node(stortree_t *root, stortree_t *node)
{
    if (root == NULL) {
        return (node);
    }
    if (root->stat.ip_addr > node->stat.ip_addr) {
        root->left = push_node(root->left, node);
        root->left->parent = root;
    }
    else if (root->stat.ip_addr < node->stat.ip_addr) {
        root->right = push_node(root->right, node);
        root->right->parent = root;
    }
    // else if (strcmp(root->stat.iface, node->stat.iface) <= 0) {
    //     root->right = push_node(root->right, node);
    //     root->right->parent = root;
    // }
    // else if (strcmp(root->stat.iface, node->stat.iface) > 0) {
    //     root->left = push_node(root->left, node);
    //     root->left->parent = root;
    // }
    return (root);
}

static stortree_t *get_gparent(stortree_t *node)
{
    if (node->parent == NULL)
        return (NULL);
    return (node->parent->parent);
}

static stortree_t *get_uncle(stortree_t *node)
{
    stortree_t *gparent;

    gparent = get_gparent(node);
    if (gparent == NULL)
        return (NULL);
    if (gparent->left == node->parent)
        return (gparent->right);
    else
        return (gparent->left);
}

static void rotate_left(stortree_t **root, stortree_t *node)
{
    stortree_t *pivot = node->right;

    pivot->parent = node->parent;
    if (node->parent == NULL)
        *root = pivot;
    else {
        if (node->parent->left == node)
            node->parent->left = pivot;
        else
            node->parent->right = pivot;
    }
    node->right = pivot->left;
    if (pivot->left != NULL)
        pivot->left->parent = node;
    node->parent = pivot;
    pivot->left = node;
}

static void rotate_right(stortree_t **root, stortree_t *node)
{
    stortree_t *pivot = node->left;

    pivot->parent = node->parent;
    if (node->parent == NULL)
        *root = pivot;
    else {
        if (node->parent->left == node)
            node->parent->left = pivot;
        else
            node->parent->right = pivot;
    }
    node->left = pivot->right;
    if (pivot->right != NULL)
        pivot->right->parent = node;
    node->parent = pivot;
    pivot->right = node;
}

static void balance_tree(stortree_t **root, stortree_t *node)
{
    stortree_t *uncle, *gparent;

    if (node->parent == NULL) {
        node->is_black = true;
        *root = node;
        return ;
    }
    if (node->parent->is_black)
        return ;
    uncle = get_uncle(node);
    gparent = get_gparent(node);
    if (uncle != NULL && !uncle->is_black) {
        node->parent->is_black = true;
        uncle->is_black = true;
        gparent->is_black = false;
        balance_tree(root, gparent);
        return ;
    }
    if (node == node->parent->right && node->parent == gparent->left) {
        rotate_left(root, node->parent);
        node = node->left;
    }
    else if (node == node->parent->left && node->parent == gparent->right) {
        rotate_right(root, node->parent);
        node = node->right;
    }
    gparent = get_gparent(node);
    node->parent->is_black = true;
    gparent->is_black = false;
    if (node == node->parent->left && node->parent == gparent->left)
        rotate_right(root, gparent);
    else
        rotate_left(root, gparent);
}

stortree_t *add_to_storage(ipstat_t *stat, uint32_t file_pos)
{
    stortree_t *node;

    node = new_node(stat, file_pos);
    if (node == NULL)
        return (NULL);
    storage = push_node(storage, node);
    balance_tree(&storage, node);
    return (node);
}

stortree_t *get_first_node(uint32_t ip_addr)
{
    stortree_t *cursor;

    cursor = storage;
    while (cursor != NULL) {
        if (cursor->stat.ip_addr == ip_addr)
            return (cursor);
        if (cursor->stat.ip_addr > ip_addr)
            cursor = cursor->left;
        else
            cursor = cursor->right;
    }
    return (NULL);
}

stortree_t *get_stor_node(uint32_t ip_addr, char *dev)
{
    stortree_t *cursor;
    int cmp;

    cursor = get_first_node(ip_addr);
    while (cursor != NULL) {
        cmp = strcmp(cursor->stat.iface, dev);
        if (cmp == 0)
            return (cursor);
        if (cmp < 0)
            cursor = cursor->left;
        else
            cursor = cursor->right; 
    }
    return (NULL);
}

static void stortree_map(stortree_t *root, void (*map_func)(stortree_t *))
{
    if (root == NULL)
        return ;
    stortree_map(root->left, map_func);
    stortree_map(root->right, map_func);
    map_func(root);
}

/*
static void print_node(stortree_t *node)
{
    char ipstr[16];
    strncpy(ipstr, itoipstr(&node->stat.ip_addr), 16);
    printf("[%16s](%8s)\t%p\tleft->%12p;\tright->%12p;\tparent->%12p\n",
            ipstr,
            node->stat.iface,
            node,
            node->left,
            node->right,
            node->parent);
}

void print_tree(void)
{
    stortree_map(storage, print_node);
}
*/

static void free_node(stortree_t *node)
{
    if (node == NULL)
        return ;
    free(node);
}

void free_storage(void)
{
    stortree_map(storage, &free_node);
    storage = NULL;
}

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

static statlist_t *new_chain(ipstat_t *stat)
{
    statlist_t *new;

    new = (statlist_t *)malloc(sizeof(statlist_t));
    if (new == NULL)
        return (NULL);
    new->stat = *stat;
    new->next = NULL;
    return (new);
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

static int add_next_same_ip(statlist_t **list,
                                    stortree_t *root,
                                    uint32_t ip_addr
)
{
    statlist_t *chain;
    int count;

    chain = new_chain(&root->stat);
    if (chain == NULL)
        return (0);
    push_to_statlist(list, chain);   
    count = 1;
    if (root->left != NULL && root->left->stat.ip_addr == ip_addr)
        count += add_next_same_ip(&chain, root->left, ip_addr);
    if (root->right != NULL && root->right->stat.ip_addr == ip_addr)
        count += add_next_same_ip(&chain, root->right, ip_addr);
    return (count);
}

int get_ip_stat(uint32_t ip_addr, statlist_t **list)
{
    statlist_t *chain;
    stortree_t *first_node;
    int count = 0;

    first_node = get_first_node(ip_addr);
    if (first_node != NULL)
        count = add_next_same_ip(list, first_node, ip_addr);
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