#define MAX_TOPLEVEL 64
#define MAX_CAPACITY 0x400000

extern struct toplevel {
    int pid;
    uint32_t sofar;
    char ops[MAX_CAPACITY];
} g_toplevel[MAX_TOPLEVEL];

void toplevel_set_root(int pid);
struct toplevel* toplevel_lookup(int pid);
struct toplevel* toplevel_lookup_create(int pid);
