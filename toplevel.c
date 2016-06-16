#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "types.h"
#include "toplevel.h"
#include "ppid.h"

struct toplevel g_toplevel[MAX_TOPLEVEL];
static uint32_t s_ntoplevel = 0;
static int s_root = -1;

static int
lookup_pid(int pid) {
    unsigned tli;
    for (tli = 0; tli < MAX_TOPLEVEL; tli++)
        if (g_toplevel[tli].pid == pid)
            break;
    return tli < MAX_TOPLEVEL ? tli : -1;
}

static int
calc_toplevel_pid(int pid) {
    int pp = ppid(pid);
    int tlpid;
    if (pp == s_root)
        tlpid = pid;
    else if (pp <= 1)
        tlpid = 1;
    else
        tlpid = calc_toplevel_pid(pp);
    return tlpid;
}

struct toplevel *
toplevel_lookup(int pid) {
    int tlpid = calc_toplevel_pid(pid);
    int tli = lookup_pid(tlpid);
    return 0 <= tli ? g_toplevel + tli : 0;
}

struct toplevel *
toplevel_lookup_create(int pid) {
    int tlpid = calc_toplevel_pid(pid);
    int tli = lookup_pid(tlpid);
    if (tli < 0) {
        struct toplevel *tl;
        tli = __sync_fetch_and_add(&s_ntoplevel, 1);
        tl = g_toplevel + tli % MAX_TOPLEVEL;
        if (tl->pid != tlpid) {
            tl->sofar = 0;
            tl->pid = tlpid;
        }
        tli = lookup_pid(tlpid);
        assert(0 <= tli);
    }
    return g_toplevel + tli;
}

void
toplevel_set_root(int pid) {
    s_root = pid;
    fprintf(stderr, "rootpid set to %d\n", s_root);
}
