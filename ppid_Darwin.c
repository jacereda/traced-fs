#include <libproc.h>
#include "ppid.h"

int
ppid(int pid) {
    struct proc_bsdinfo bi;
    int r = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof(bi));
    return r ? bi.pbi_ppid : 0;
}
