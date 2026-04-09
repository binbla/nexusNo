CXX ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -pedantic

INCLUDES := -I../include -I../external/BLAKE2/sse
SOURCES := crypto_test.cpp ../src/crypto/crypto.cpp ../external/BLAKE2/sse/blake2s.c
LDFLAGS := -lsodium

TARGET := crypto_test

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SOURCES) $(LDFLAGS) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
