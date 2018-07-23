CC=gcc
CFLAGS=-Wall -Werror -Wconversion
LIBFLAGS=-lpcap -lpthread

NAME=pcountd
INC=sniffer.h
SRC=main.c daemon.c cli.c sniffer.c file_stor.c print_stats.c commands.c\
	mem_stor.c stat_list.c stat_list_if.c socket.c
OBJ=$(SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	@$(CC) $(CFLAGS) -I. $(OBJ) $(LIBFLAGS) -o $@

%.o: %.c $(INC)
	@$(CC) $(CFLAGS) -I. $(LIBFT_INCLUDE_FLAGS) -c $< -o $@

clean:
	@rm -f $(OBJ)

fclean: clean
	@rm -f $(NAME)

re: fclean all
