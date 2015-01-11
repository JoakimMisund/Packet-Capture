CFLAGS = -c -g -Wall
CC = gcc
LDFLAGS = -o
LD = gcc

all: packetsniffer
.phony: clean

packetsniffer: packetsniffer.o
	$(LD) $(LDFLAGS)  packetsniffer Packetsniffer.o -lpcap

packetsniffer.o: Packetsniffer.cpp
	$(CC) $(CFLAGS) Packetsniffer.cpp

clean:
	rm -f *.o packetsniffer
