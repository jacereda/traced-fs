all: fs fsd

fs: fs.c
	$(CC) -DNDEBUG -O2 -fno-stack-protector -fomit-frame-pointer -Wall `pkg-config fuse --cflags --libs` $^ -o $@

fsd: fs.c
	$(CC) -O1 -fsanitize=address -fno-omit-frame-pointer -Wall `pkg-config fuse --cflags --libs` $^ -o $@


