CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
LDFLAGS = -lpcap

CHECK_LIBRESOLV := $(shell echo 'int main() { return 0; }' | $(CC) -x c - -lresolv -o /dev/null 2>/dev/null && echo "-lresolv" || echo "")

LDFLAGS += $(CHECK_LIBRESOLV)

TARGET = dns-monitor
SOURCES = dns-monitor.c argparse.c pcapinit.c dns_utils.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $(TARGET) 2>/dev/null || $(CC) $(OBJECTS) -lpcap -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
