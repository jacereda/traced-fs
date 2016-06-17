#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "types.h"
#include "toplevel.h"
#include "op.h"

static int
opchar(enum op op) {
    int r;
    switch (op) {
        case OP_READ:
            r = 'r';
            break;
        case OP_WRITE:
            r = 'w';
            break;
        case OP_QUERY:
            r = 'q';
            break;
        case OP_RENAME:
            r = 'm';
            break;
        case OP_DELETE:
            r = 'd';
            break;
        case OP_LIST:
            r = 'l';
            break;
        case OP_LINK:
            r = 'k';
            break;
        case OP_MAX:
            assert(0);
            r = 0;
            break;
    }
    return r;
}

void
op_register(struct toplevel *tl, enum op op, const char *p1, const char *p2) {
    char *p;
    size_t s1 = strlen(p1);
    size_t s2 = p2 ? strlen(p2) : 0;
    size_t sofar;
    size_t sz = 1               // op
                + 1             // |
                + s1            // p1
                + (p2 ? 1 : 0)  // |
                + s2            // p2
                + 1             // \n
        ;
    sofar = __sync_fetch_and_add(&tl->sofar, sz);
    if (sofar + sz < MAX_CAPACITY) {
        p = tl->ops + sofar;
        *p++ = opchar(op);
        *p++ = '|';
        memcpy(p, p1, s1);
        p += s1;
        if (p2) {
            *p++ = '|';
            memcpy(p, p2, s2);
            p += s2;
        }
        *p++ = '\n';
    } else {
        fprintf(stderr, "Maximum capacity reached, wrapping\n");
        tl->sofar = 0;
    }
}
