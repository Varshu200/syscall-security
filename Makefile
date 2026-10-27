CC      = gcc
CFLAGS  = -Wall -Wextra -g -O0
LDLIBS  = -lseccomp

sandbox: src/main.c
	$(CC) $(CFLAGS) -o sandbox src/main.c $(LDLIBS)

clean:
	rm -f sandbox
