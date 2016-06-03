all: fs fsd

fs: fs.c
	$(CC) -DNDEBUG -O2 -fno-stack-protector -fomit-frame-pointer -Wall `pkg-config fuse --cflags --libs` $^ -o $@

fsd: fs.c
	$(CC) -g -O0 -Wall `pkg-config fuse --cflags --libs` $^ -o $@


