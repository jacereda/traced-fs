OS=$(shell uname -s)
SRCS=src/fs.c src/op.c src/toplevel.c src/ppid_$(OS).c
CFLAGS=-Wall

all: fs fsd

fs: $(SRCS)
	$(CC) $(CFLAGS) -DNDEBUG -O2 -fno-stack-protector -fomit-frame-pointer -Wall `pkg-config fuse --cflags --libs` $^ -o $@

fsd: $(SRCS)
	$(CC) $(CFLAGS) -g -O0 `pkg-config fuse --cflags --libs` $^ -o $@


htest: all
	cd test && stack test
