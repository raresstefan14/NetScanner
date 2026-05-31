CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -Iinclude
SRC     = src/main.c src/scanner.c src/utils.c src/threadpool.c src/cidr.c src/udp_scanner.c src/os_detect.c
TARGET  = netscanner

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lpthread

clean:
	rm -f $(TARGET)
