# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Libraries
LIBS = -lssl -lcrypto -lpthread

# Source file
SRC = http_downloader.c

# Output executable
OUT = http_downloader

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LIBS)

clean:
	rm -f $(OUT)
	rm -f *.gif
	rm -f part_*
	rm -f *.jpg