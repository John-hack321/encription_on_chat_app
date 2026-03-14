CC     = gcc
CFLAGS = -Wall -Wextra -g

SRC = src/main.c \
      src/common/user_manager.c

all:
	$(CC) $(CFLAGS) $(SRC) -o chat

clean:
	rm -f chat