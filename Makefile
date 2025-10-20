CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lssl -lcrypto
TARGET = dns_forwarder

all: $(TARGET)

$(TARGET): dns_forwarder.c
	$(CC) $(CFLAGS) -o $(TARGET) dns_forwarder.c $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean