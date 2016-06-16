OS=$(shell uname -s)
SRCS=fs.c toplevel.c ppid_$(OS).c

all: fs fsd

fs: $(SRCS)
	$(CC) -DNDEBUG -O2 -fno-stack-protector -fomit-frame-pointer -Wall `pkg-config fuse --cflags --libs` $^ -o $@

fsd: $(SRCS)
	$(CC) -g -O0 -Wall `pkg-config fuse --cflags --libs` $^ -o $@


