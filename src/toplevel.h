struct toplevel {
    int pid;
    uint32_t sofar;
    char ops[MAX_CAPACITY];
};

extern struct toplevel g_toplevel[MAX_TOPLEVEL];

void toplevel_set_root(int pid);
struct toplevel* toplevel_lookup(int pid);
struct toplevel* toplevel_lookup_create(int pid);
