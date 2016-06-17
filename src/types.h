#define MAX_TOPLEVEL 64
#define MAX_CAPACITY 0x400000

enum op {
    OP_READ,
    OP_WRITE,
    OP_QUERY,
    OP_RENAME,
    OP_DELETE,
    OP_LIST,
    OP_LINK,
    OP_MAX,
};
