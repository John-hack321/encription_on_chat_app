CC     = gcc
CFLAGS = -Wall -Wextra -g
LIBS   = -lssl -lcrypto

COMMON = src/common/auth.c \
         src/common/user_manager.c \
         src/common/message_handler.c \
         src/common/utils.c \
         src/common/crypto.c

all: server client keygen

server:
	$(CC) $(CFLAGS) src/server_main.c src/server/server.c $(COMMON) $(LIBS) -o server

client:
	$(CC) $(CFLAGS) src/client_main.c src/client/client.c $(COMMON) $(LIBS) -o client

keygen:
	$(CC) $(CFLAGS) src/keygen_main.c $(COMMON) $(LIBS) -o keygen

clean:
	rm -f server client keygen