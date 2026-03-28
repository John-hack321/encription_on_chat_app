CC     = gcc
CFLAGS = -Wall -Wextra -g

# shared modules used by both binaries
COMMON = src/common/auth.c \
         src/common/user_manager.c \
         src/common/message_handler.c \
         src/common/utils.c

all: server client

# server binary — server_main.c is the entry point
server:
	$(CC) $(CFLAGS) src/server_main.c src/server/server.c $(COMMON) -o server

# client binary — client_main.c is the entry point
client:
	$(CC) $(CFLAGS) src/client_main.c src/client/client.c $(COMMON) -o client

clean:
	rm -f server client