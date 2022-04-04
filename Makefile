CPPFLAGS=-Wall -Wextra -g
LDFLAGS=-lpcap

BIN=ipk-sniffer

all: $(BIN)

pack: ipk-sniffer.cpp Makefile
	zip xmatus36.zip $^

clean:
	-$(RM) $(BIN)

.PHONY: all pack clean
