CC = g++
CFLAGS = -Wall -std=c++11 -g
LDFLAGS = -lmiracl

COMMON_SRCS = HPoW.cpp PRG.cpp MerkleTree.cpp Parameter.cpp Auditor.cpp Client.cpp Verifier.cpp
COMMON_HEADERS = $(COMMON_SRCS:.cpp=.h)

SOURCES = main.cpp
HEADERS = $(COMMON_HEADERS)

all: popa

popa: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(COMMON_SRCS) $(LDFLAGS)

clean:
	rm -f popa

