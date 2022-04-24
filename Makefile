CXXFLAGS=-Wall -Wextra
LDFLAGS=-lpcap

BIN=ipk-sniffer
DOCSNAME=manual

all: $(BIN)

$(BIN): ipk-sniffer.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

docs: $(DOCSNAME).tex
	pdflatex $^
	pdflatex $^

pack: ipk-sniffer.cpp Makefile README.md manual.pdf
	tar -cvf xmatus36.tar $^

clean:
	-$(RM) $(BIN)

.PHONY: all pack clean
