CXXFLAGS=-Wall -Wextra -g
LDFLAGS=-lpcap

BIN=ipk-sniffer

all: $(BIN)

$(BIN): ipk-sniffer.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

pack: ipk-sniffer.cpp Makefile
	zip xmatus36.zip $^

clean:
	-$(RM) $(BIN)

.PHONY: all pack clean
