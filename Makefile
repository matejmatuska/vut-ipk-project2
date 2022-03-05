CPPFLAGS=-Wall -Wextra -g
LDFLAGS=-lpcap

BIN=ipk-sniffer

all: $(BIN)

clean:
	-$(RM) $(BIN)

.PHONY: all clean
