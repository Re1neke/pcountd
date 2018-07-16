#include <sniffer.h>

bool is_cli = false;

int main(int argc, char *argv[])
{
    set_iface(NULL);
    new_memstor();
    file_to_memory();
    if (argc == 1) {
        is_cli = true;
        run_cli();
    }
    else
        select_command(argc - 1, &argv[1]);
    return (0);
}
