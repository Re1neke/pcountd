#include <sniffer.h>

int main(int argc, char *argv[])
{
    if (getuid() != 0) {
        fprintf(stderr, "Must be root for correct working.\n");
        exit(EXIT_FAILURE);
    }
    set_iface(NULL);
    new_memstor();
    file_to_memory();
    if (argc == 1)
        run_cli();
    else
        select_command(argc - 1, &argv[1]);
    return (0);
}
