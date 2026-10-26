CC     = gcc
CFLAGS = -Wall -Wextra -g -O0

sandbox: src/main.c
	$(CC) $(CFLAGS) -o sandbox src/main.c

clean:
	rm -f sandbox
