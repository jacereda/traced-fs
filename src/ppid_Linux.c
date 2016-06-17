#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "ppid.h"

int
ppid(int pid) {
    char buf[64];
    int fd;
    char *spid;
    snprintf(buf, sizeof(buf), "/proc/%d/stat", pid);
    fd = open(buf, O_RDONLY);
    read(fd, buf, sizeof(buf));
    close(fd);
    spid = strchr(buf, ')');
    return atoi(spid + 3);
}
