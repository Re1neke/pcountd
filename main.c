#include <sniffer.h>

int main(int argc, char *argv[])
{
    set_iface(NULL);
    if (argc == 1)
        run_cli();
    else
        select_command(argc - 1, &argv[1]);
    return (0);
}
