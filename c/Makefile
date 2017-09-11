TARGET = kerltest
CC = gcc
CFLAGS = -g -Wall
INCLUDE = -Iexternal/bignum/out/ -Iinc
LIB = -Lexternal/bignum/out/
LIBS = $(LIB) -lbignum

.PHONY: default all clean init pretty

default: $(TARGET)
all: default

debug: CFLAGS += -DDEBUG -g -O0
debug: default

SOURCES = $(wildcard *.c) \
	external/Keccak-readable-and-compact.c \
	$(wildcard test/*.c)

HEADERS = $(wildcard *.h) \
	$(wildcard external/out/*.h)

OBJECTS = $(patsubst %.c, %.o, $(SOURCES))

pretty:
	astyle  --style=kr --indent=spaces=2 $(SOURCES) $(HEADERS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

clean:
	-rm -f $(OBJECTS)
	-rm -f $(TARGET)