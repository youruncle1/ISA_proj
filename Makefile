CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDFLAGS = -lpcap

TARGET = dns-monitor
SOURCES = dns-monitor.c argparse.c pcapinit.c dns_utils.c

OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
