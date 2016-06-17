OS=$(shell uname -s)
SRCS=src/fs.c src/op.c src/toplevel.c src/ppid_$(OS).c
CFLAGS=-Wall

all: fs fsd

fs: $(SRCS)
	$(CC) $(CFLAGS) -DNDEBUG -O2 -fno-stack-protector -fomit-frame-pointer -Wall `pkg-config fuse --cflags --libs` $^ -o $@

fsd: $(SRCS)
	$(CC) $(CFLAGS) -g -O0 `pkg-config fuse --cflags --libs` $^ -o $@


test: all
	./fsd traced
	-stat traced/.rootpid-$$PPID
	cp traced/bin/ls traced/tmp/foo
	mv traced/tmp/foo traced/tmp/bar
	touch traced/tmp/bar
	rm traced/tmp/bar
	sh -c "cp traced/bin/ls traced/tmp/foo && mv traced/tmp/foo traced/tmp/bar && rm traced/tmp/bar"
	cc -c -D_GNU_SOURCE -D_BSD_SOURCE=1 -std=c99 -Wall traced/`pwd`/src/toplevel.c -o traced/tmp/toplevel.o
	ls -l traced/.ops/
	cat traced/.ops/*
	umount traced


htest: all
	cd test && stack test
