CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap
TARGET = decap_vxlan
PREFIX = /usr/local

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/

clean:
	rm -f $(TARGET)
