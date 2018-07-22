#include <sniffer.h>

bool is_cli = false;

static int count_tokens(char *str)
{
    int count = 0;

    if (str == NULL)
        return (0);
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isspace(str[i]) && isspace(str[i + 1]))
            count++;
    }
    return (count);
}

static char **strtoarr(char *str, int *count)
{
    char **array;
    char *tmp;

    *count = count_tokens(str);
    if (*count < 1)
        return (NULL);
    array = malloc(sizeof(char *) * (unsigned long)*count);
    if (array == NULL)
        return (NULL);
    tmp = strtok(str, " \t\n");
    for (int i = 0; tmp != NULL; i++) {
        array[i] = tmp;
        tmp = strtok(NULL, " \t\n");
    }
    return (array);
}

void run_cli(void)
{
    char **argv;
    char *line;
    int argc;
    size_t buflen;

    is_cli = true;
    if (read_pidfile() > 0)
        printf("The daemon is running now.\n");
    else
        printf("The daemon is not running.\n");
    while (true) {
        buflen = 0;
        line = NULL;
        fputs( "> ", stdout);
        getline(&line, &buflen, stdin);
        argv = strtoarr(line, &argc);
        if (argv != NULL) {
            select_command(argc, argv);
            free(argv);
        }
        if (line != NULL)
            free(line);
    }
}
