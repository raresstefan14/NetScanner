CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -Iinclude
SRC     = src/main.c src/scanner.c src/utils.c
TARGET  = netscanner

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lpthread
clean:
	rm -f $(TARGET)