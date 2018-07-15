CC=clang
CFLAGS=-Wall -Werror -Wconversion
LIBFLAGS=-lpcap

NAME=pcountd
INC=sniffer.h
SRC=main.c daemon.c commands.c cli.c sniffer.c
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
