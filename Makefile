OS=$(shell uname -s)
SRCS=fs.c op.c toplevel.c ppid_$(OS).c
CFLAGS=-Wall

all: fs fsd

fs: $(SRCS)
	$(CC) $(CFLAGS) -DNDEBUG -O2 -fno-stack-protector -fomit-frame-pointer -Wall `pkg-config fuse --cflags --libs` $^ -o $@

fsd: $(SRCS)
	$(CC) $(CFLAGS) -g -O0 `/usr/local/bin/pkg-config fuse --cflags --libs` $^ -o $@


