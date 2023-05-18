CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap
TARGET = decap_vxlan

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
