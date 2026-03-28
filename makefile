CC     = gcc
CFLAGS = -Wall -Wextra -g

COMMON = src/common/auth.c \
        src/common/user_manager.c \
        src/common/message_handler.c \
        src/common/utils.c

all: server client

server:
	$(CC) $(CFLAGS) src/server_main.c src/server/server.c $(COMMON) -o server

client:
	$(CC) $(CFLAGS) src/client_main.c src/client/client.c $(COMMON) -o client

clean:
	rm -f server client