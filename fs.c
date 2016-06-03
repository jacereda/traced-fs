#define FUSE_USE_VERSION 26

#if defined __linux__
#define HAVE_SETXATTR
#define HAVE_UTIMENSAT
#define HAVE_FDATASYNC
#endif

#if defined __APPLE__
#define HAVE_SETXATTR
#define G_PREFIX "org"
#define G_KAUTH_FILESEC_XATTR G_PREFIX ".apple.system.Security"
#define A_PREFIX "com"
#define A_KAUTH_FILESEC_XATTR A_PREFIX ".apple.system.Security"
#define XATTR_APPLE_PREFIX "com.apple."
#endif

#define _GNU_SOURCE

#include <fuse.h>

#ifdef HAVE_LIBULOCKMGR
#include <ulockmgr.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/mount.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#if defined __APPLE__
#include <libproc.h>
#endif

#define MAX_TOPLEVEL 64
#define MAX_CAPACITY (1024 * 1024)

struct toplevel {
    int pid;
    uint32_t sofar;
    char ops[MAX_CAPACITY];
};

static struct toplevel s_toplevel[MAX_TOPLEVEL] = {{0}};
static uint32_t s_ntoplevel = 0;
static int s_root = 0;
static const char *s_generator = 0;

struct fsat_dirh {
    DIR *dp;
    struct toplevel *tl;
    struct dirent *entry;
    off_t offset;
    char path[PATH_MAX];
};

struct fsat_fileh {
    struct toplevel *tl;
    int fd;
    char path[PATH_MAX];
};

static int
lookup_pid(int pid) {
    unsigned tli;
    for (tli = 0; tli < MAX_TOPLEVEL; tli++)
        if (s_toplevel[tli].pid == pid)
            break;
    return tli < MAX_TOPLEVEL ? tli : -1;
}

static int
calc_ppid(int pid) {
#if defined __APPLE__
    struct proc_bsdinfo bi;
    int r = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof(bi));
    return r ? bi.pbi_ppid : 0;
#endif
#if defined __linux__
    char buf[64];
    int fd;
    char *spid;
    snprintf(buf, sizeof(buf), "/proc/%d/stat", pid);
    fd = open(buf, O_RDONLY);
    read(fd, buf, sizeof(buf));
    close(fd);
    spid = strchr(buf, ')');
    return atoi(spid + 3);
#endif
}

static int
calc_toplevel_pid(int pid) {
    int ppid = calc_ppid(pid);
    int tlpid;
    if (ppid == s_root)
        tlpid = pid;
    else if (ppid <= 1)
        tlpid = 1;
    else
        tlpid = calc_toplevel_pid(ppid);
    return tlpid;
}

struct toplevel *
lookup_toplevel() {
    struct fuse_context *ctx = fuse_get_context();
    if (!ctx->private_data) {
        int tlpid = calc_toplevel_pid(ctx->pid);
        int tli = lookup_pid(tlpid);
        if (tli < 0) {
            struct toplevel *tl;
            tli = __sync_fetch_and_add(&s_ntoplevel, 1);
            tl = s_toplevel + tli % MAX_TOPLEVEL;
            if (tl->pid != tlpid) {
                tl->sofar = 0;
                tl->pid = tlpid;
            }
            tli = lookup_pid(tlpid);
            assert(tli >= 0);
        }
        ctx->private_data = s_toplevel + tli;
    }
    return ctx->private_data;
}

static uintptr_t
fillfh(struct fsat_fileh *f, const char *path, int fd, struct toplevel *tl) {
    strncpy(f->path, path, PATH_MAX);
    f->path[PATH_MAX - 1] = 0;
    f->fd = fd;
    f->tl = tl;
    return (uintptr_t)f;
}

static uintptr_t
filldh(struct fsat_dirh *d, const char *path, DIR *dp, struct toplevel *tl) {
    strncpy(d->path, path, PATH_MAX);
    d->path[PATH_MAX - 1] = 0;
    d->dp = dp;
    d->tl = tl;
    d->offset = 0;
    d->entry = 0;
    return (uintptr_t)d;
}

static inline struct fsat_dirh *
dirh(struct fuse_file_info *fi) {
    return (struct fsat_dirh *)(uintptr_t)fi->fh;
}

static inline struct fsat_fileh *
fileh(struct fuse_file_info *fi) {
    return (struct fsat_fileh *)(uintptr_t)fi->fh;
}

static ssize_t
sszmin(ssize_t a, ssize_t b) {
    return a < b ? a : b;
}

static ssize_t
sszmax(ssize_t a, ssize_t b) {
    return b < a ? a : b;
}

static ssize_t
sszclamp(ssize_t min, ssize_t x, ssize_t max) {
    return sszmax(min, sszmin(x, max));
}

static void
op2(int o, const char *p1, const char *p2) {
    struct toplevel *tl = lookup_toplevel();
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
        *p++ = o;
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

static void
op1(int o, const char *p1) {
    op2(o, p1, 0);
}

static const char *s_ops = "/.ops";
static const int s_opslen = 5;

static int
is_ops(const char *path) {
    return 0 == strncmp(path, s_ops, s_opslen);
}

static int
ops_pid(const char *path) {
    int r;
    assert(is_ops(path));
    if (0 == path[s_opslen])
        r = 0;
    else
        r = atoi(path + s_opslen + 1);
    return r;
}

static int
generate(const char *path) {
    int r;
    if (s_generator) {
        char buf[PATH_MAX + 32];
        snprintf(buf, sizeof(buf), "%s '%s'", s_generator, path);
        r = 0 == system(buf);
    } else
        r = 0;
    return r;
}

static int
stat_toplevel(struct toplevel *tl, struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_nlink = 1;
    st->st_size = tl->sofar;
    st->st_mode = S_IFREG | 0444;
    return 0;
}

static void
stat_root(struct stat *st) {
    memset(st, 0, sizeof(*st));
    st->st_nlink = 2;
    st->st_mode = S_IFDIR | 0555;
}

static int
stat_ops(const char *path, struct stat *st) {
    int pid = ops_pid(path);
    int r = 0;
    if (0 == pid) {
        stat_root(st);
        r = 0;
    } else {
        int tli = lookup_pid(pid);
        if (0 <= tli) {
            stat_toplevel(s_toplevel + tli, st);
            r = 0;
        } else {
            errno = ENOENT;
            r = -1;
        }
    }
    return r;
}

static int
fsat_getattr(const char *path, struct stat *st) {
    int r;
    if (is_ops(path))
        r = stat_ops(path, st);
    else
        r = lstat(path, st);
    if (0 == r)
        op1('q', path);
    else if (generate(path))
        r = -fsat_getattr(path, st);
    return 0 == r ? 0 : -errno;
}

static int
fsat_fgetattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    struct fsat_fileh *f = fileh(fi);
    int r;
    if (0 <= f->fd)
        r = fstat(f->fd, st);
    else
        r = stat_toplevel(f->tl, st);
    if (0 == r)
        op1('q', f->path);
    else if (generate(path))
        r = -fsat_fgetattr(path, st, fi);
    return 0 == r ? 0 : -errno;
}

static int
fsat_access(const char *path, int mask) {
    int r;
    if (is_ops(path))
        r = 0;
    else
        r = access(path, mask);
    if (0 == r)
        op1('q', path);
    else if (generate(path))
        r = -fsat_access(path, mask);
    return 0 == r ? 0 : -errno;
}

static int
fsat_readlink(const char *path, char *buf, size_t size) {
    int r;
    r = readlink(path, buf, size - 1);
    if (0 <= r) {
        buf[r] = '\0';
        op1('r', path);
    } else
        generate(path);
    return 0 <= r ? 0 : -errno;
}

static int
fsat_opendir(const char *path, struct fuse_file_info *fi) {
    DIR *dp = 0;
    struct toplevel *tl = 0;
    int r;
    if (is_ops(path)) {
        tl = s_toplevel;
        fi->direct_io = 1;
    } else
        dp = opendir(path);
    if (tl || dp) {
        struct fsat_dirh *d = malloc(sizeof(*d));
        if (d) {
            fi->fh = filldh(d, path, dp, tl);
            r = 0;
        } else
            r = -ENOMEM;
    } else
        r = -ENOENT;
    return r;
}

static int
fsat_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
             struct fuse_file_info *fi) {
    struct fsat_dirh *d = dirh(fi);

    if (d->tl) {
        unsigned i;
        for (i = 0; i < MAX_TOPLEVEL; i++) {
            struct toplevel *tl = s_toplevel + i;
            char nm[32];
            struct stat st;
            if (!tl->pid)
                continue;
            snprintf(nm, sizeof(nm), "%d", tl->pid);
            stat_toplevel(tl, &st);
            filler(buf, nm, &st, 0);
        }
    } else {
        if (0 == d->path[1] && 0 == offset) {
            struct stat st;
            st.st_nlink = 2;
            st.st_size = 0;
            st.st_mode = S_IFDIR | 0555;
            filler(buf, s_ops + 1, &st, 0);
        }

        if (offset != d->offset) {
            seekdir(d->dp, offset);
            d->entry = 0;
            d->offset = offset;
        }
        while (1) {
            struct stat st;
            off_t nextoff;

            if (!d->entry) {
                d->entry = readdir(d->dp);
                if (!d->entry)
                    break;
            }
#ifdef HAVE_FSTATAT
            if (flags & FUSE_READDIR_PLUS) {
                int r = fstatat(dirfd(d->dp), d->entry->d_name, &st,
                                AT_SYMLINK_NOFOLLOW);
                if (r != -1)
                    fill_flags |= FUSE_FILL_DIR_PLUS;
            }
#endif
            memset(&st, 0, sizeof(st));
            st.st_ino = d->entry->d_ino;
            st.st_mode = d->entry->d_type << 12;
            nextoff = telldir(d->dp);
            if (filler(buf, d->entry->d_name, &st, nextoff))
                break;

            d->entry = 0;
            d->offset = nextoff;
        }
        op1('l', d->path);
    }
    return 0;
}

static int
fsat_releasedir(const char *path, struct fuse_file_info *fi) {
    struct fsat_dirh *d = dirh(fi);
    if (d->dp)
        closedir(d->dp);
    free(d);
    return 0;
}

static int
fsat_mknod(const char *path, mode_t mode, dev_t rdev) {
    int r;
    if (S_ISFIFO(mode))
        r = mkfifo(path, mode);
    else
        r = mknod(path, mode, rdev);
    if (0 == r)
        op1('w', path);
    return 0 == r ? 0 : -errno;
}

static int
fsat_mkdir(const char *path, mode_t mode) {
    int r = mkdir(path, mode);
    if (0 == r)
        op1('w', path);
    return 0 == r ? 0 : -errno;
}

static int
fsat_unlink(const char *path) {
    int r = unlink(path);
    if (0 == r)
        op1('d', path);
    return 0 == r ? 0 : -errno;
}

static int
fsat_rmdir(const char *path) {
    int r = rmdir(path);
    if (0 == r)
        op1('d', path);
    return 0 == r ? 0 : -errno;
}

static int
fsat_symlink(const char *from, const char *to) {
    int r = symlink(from, to);
    if (0 == r)
        op2('k', to, from);
    return 0 == r ? 0 : -errno;
}

static int
fsat_rename(const char *from, const char *to) {
    int r = rename(from, to);
    if (0 == r)
        op2('m', to, from);
    return 0 == r ? 0 : -errno;
}

static int
fsat_link(const char *from, const char *to) {
    int r = link(from, to);
    if (0 == r)
        op2('k', to, from);
    return 0 == r ? 0 : -errno;
}

static int
fsat_chmod(const char *path, mode_t mode) {
    int r = chmod(path, mode);
    if (0 == r)
        op1('w', path);
    return 0 == r ? 0 : -errno;
}

static int
fsat_chown(const char *path, uid_t uid, gid_t gid) {
    int r = lchown(path, uid, gid);
    if (0 == r)
        op1('w', path);
    return 0 == r ? 0 : -errno;
}

static int
fsat_truncate(const char *path, off_t size) {
    int r = truncate(path, size);
    if (0 == r)
        op1('w', path);
    return 0 == r ? 0 : -errno;
}

static int
fsat_ftruncate(const char *path, off_t size, struct fuse_file_info *fi) {
    int r;
    struct fsat_fileh *f = fileh(fi);
    if (0 <= f->fd)
        r = ftruncate(f->fd, size);
    else {
        errno = ENOENT;
        r = -1;
    }
    if (0 == r)
        op1('w', f->path);
    return 0 == r ? 0 : -errno;
}

#ifdef HAVE_UTIMENSAT
static int
fsat_utimens(const char *path, const struct timespec ts[2]) {
    int r = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
    if (0 == r)
        op1('w', path);
    return 0 == r ? 0 : -errno;
}
#endif

static int
fsat_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int fd;
    struct fsat_fileh *f;
    int r = 0;
    assert(!is_ops(path));
    fd = open(path, fi->flags, mode);
    if (fd < 0)
        r = -errno;
    if (!r)
        f = malloc(sizeof(*f));
    if (!r && !f)
        r = -ENOMEM;
    if (!r && f) {
        fi->fh = fillfh(f, path, fd, 0);
        op1('w', f->path);
    }
    return r;
}

static struct toplevel *
open_ops(const char *path) {
    int pid = ops_pid(path);
    int tli = lookup_pid(pid);
    if (tli < 0)
        errno = ENOENT;
    return tli < 0 ? 0 : s_toplevel + tli;
}

static int
fsat_open(const char *path, struct fuse_file_info *fi) {
    struct fsat_fileh *f;
    struct toplevel *tl;
    int fd = -1;
    int r = 0;
    if (is_ops(path)) {
        tl = open_ops(path);
        fd = -1;
        fi->direct_io = 1;
    } else {
        fd = open(path, fi->flags);
        tl = 0;
    }
    if (fd < 0 && !tl)
        r = -errno;
    if (!r)
        f = malloc(sizeof(*f));
    if (!r && !f)
        r = -ENOMEM;
    if (!r)
        fi->fh = fillfh(f, path, fd, tl);
    return r;
}

static int
read_ops(struct toplevel *tl, char *buf, size_t size, off_t offset) {
    size_t sz;
    assert(tl);
    sz = sszclamp(0, size, tl->sofar - offset);
    memcpy(buf, tl->ops + offset, sz);
    return sz;
}

static int
fsat_read(const char *path, char *buf, size_t size, off_t offset,
          struct fuse_file_info *fi) {
    int r;
    struct fsat_fileh *f = fileh(fi);
    if (0 <= f->fd)
        r = pread(f->fd, buf, size, offset);
    else
        r = read_ops(f->tl, buf, size, offset);
    if (0 <= r)
        op1('r', f->path);
    return 0 <= r ? r : -errno;
}

static int
fsat_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size,
              off_t offset, struct fuse_file_info *fi) {
    struct fuse_bufvec *src;
    struct fuse_buf *b = 0;
    struct fsat_fileh *f = fileh(fi);
    struct toplevel *tl = f->tl;
    int fd = f->fd;
    ssize_t sz = 0;
    int r = 0;
    src = malloc(sizeof(*src));
    if (!src)
        r = -ENOMEM;
    if (!r) {
        sz = 0 <= fd ? size : sszclamp(0, tl->sofar - offset, size);
        *src = FUSE_BUFVEC_INIT(sz);
        b = src->buf;
        b->pos = offset;
    }
    if (!r && 0 <= fd) {
        b->flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
        b->fd = fd;
    }
    if (!r && tl)
        b->mem = malloc(sz);
    if (!r && tl && !b->mem)
        r = -ENOMEM;
    if (!r && tl)
        memcpy(b->mem, tl->ops + offset, sz);
    if (r && b && b->mem)
        free(b->mem);
    if (r && src)
        free(src);
    if (!r) {
        *bufp = src;
        op1('r', f->path);
    }
    return r;
}

static int
fsat_write(const char *path, const char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi) {
    int r;
    struct fsat_fileh *f = fileh(fi);
    if (0 <= f->fd)
        r = pwrite(f->fd, buf, size, offset);
    else {
        errno = ENOENT;
        r = -1;
    }
    if (0 <= r)
        op1('w', f->path);
    return 0 <= r ? r : -errno;
}

static int
fsat_write_buf(const char *path, struct fuse_bufvec *buf, off_t offset,
               struct fuse_file_info *fi) {
    struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));
    struct fuse_buf *b = dst.buf;
    struct fsat_fileh *f = fileh(fi);
    int r;
    assert(0 <= f->fd);
    if (0 <= f->fd) {
        b->flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
        b->fd = f->fd;
        b->pos = offset;
        op1('w', f->path);
        r = fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
    } else
        r = -ENOENT;
    return r;
}

static int
fsat_statfs(const char *path, struct statvfs *stbuf) {
    int r = statvfs(path, stbuf);
    return r == 0 ? 0 : -errno;
}

static int
fsat_flush(const char *path, struct fuse_file_info *fi) {
    int r;
    struct fsat_fileh *f = fileh(fi);
    if (0 <= f->fd)
        r = close(dup(f->fd));
    else
        r = 0;
    return r == 0 ? 0 : -errno;
}

static int
fsat_release(const char *path, struct fuse_file_info *fi) {
    struct fsat_fileh *f = fileh(fi);
    if (0 <= f->fd)
        close(f->fd);
    free(f);
    return 0;
}

static int
fsat_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    int r;
    struct fsat_fileh *f = fileh(fi);
#ifdef HAVE_FDATASYNC
    if (isdatasync)
        r = 0 <= f->fd ? fdatasync(f->fd) : 0;
    else
#endif
        r = 0 <= f->fd ? fsync(f->fd) : 0;
    return 0 == r ? 0 : -errno;
}

#ifdef HAVE_POSIX_FALLOCATE
static int
fsat_fallocate(const char *path, int mode, off_t offset, off_t length,
               struct fuse_file_info *fi) {
    struct fsat_fileh *f = fileh(fi);
    int r;
    assert(0 <= f->fd);
    if (mode)
        r = EOPNOTSUPP;
    else
        r = posix_fallocate(f->fd, offset, length);
    if (0 == r)
        op1('w', f->path);
    return 0 == r ? 0 : -r;
}
#endif

#ifdef HAVE_SETXATTR
static int
fsat_setxattr(const char *path, const char *name, const char *value,
              size_t size, int flags
#if defined __APPLE__
              ,
              uint32_t position
#endif
              ) {
#if defined __APPLE__
    int r;
    if (!strncmp(name, XATTR_APPLE_PREFIX, sizeof(XATTR_APPLE_PREFIX) - 1)) {
        flags &= ~(XATTR_NOSECURITY);
    }
    if (!strcmp(name, A_KAUTH_FILESEC_XATTR)) {
        char new_name[MAXPATHLEN];
        memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
        memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
        r = setxattr(path, new_name, value, size, position, flags);
    } else {
        r = setxattr(path, name, value, size, position, flags);
    }

#else
    int r = lsetxattr(path, name, value, size, flags);
#endif
    if (0 == r)
        op1('w', path);
    return 0 == r ? 0 : -errno;
}

static int
fsat_getxattr(const char *path, const char *name, char *value, size_t size
#if defined __APPLE__
              ,
              uint32_t position
#endif
              ) {
#if defined __APPLE__
    int r;
    if (strcmp(name, A_KAUTH_FILESEC_XATTR) == 0) {
        char new_name[MAXPATHLEN];
        memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
        memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
        r = getxattr(path, new_name, value, size, position, XATTR_NOFOLLOW);
    } else {
        r = getxattr(path, name, value, size, position, XATTR_NOFOLLOW);
    }
#else
    int r = lgetxattr(path, name, value, size);
#endif
    if (0 <= r)
        op1('q', path);
    return 0 <= r ? r : -errno;
}

static int
fsat_listxattr(const char *path, char *list, size_t size) {
#if defined __APPLE__
    ssize_t r = listxattr(path, list, size, XATTR_NOFOLLOW);
    if (r > 0) {
        if (list) {
            size_t len = 0;
            char *curr = list;
            do {
                size_t thislen = strlen(curr) + 1;
                if (strcmp(curr, G_KAUTH_FILESEC_XATTR) == 0) {
                    memmove(curr, curr + thislen, r - len - thislen);
                    r -= thislen;
                    break;
                }
                curr += thislen;
                len += thislen;
            } while (len < r);
        } else {
            /*
            ssize_t res2 = getxattr(path, G_KAUTH_FILESEC_XATTR, NULL, 0, 0,
                                    XATTR_NOFOLLOW);
            if (res2 >= 0) {
                    res -= sizeof(G_KAUTH_FILESEC_XATTR);
            }
            */
        }
    }
#else
    int r = llistxattr(path, list, size);
#endif
    if (0 <= r)
        op1('q', path);
    return 0 <= r ? r : -errno;
}

static int
fsat_removexattr(const char *path, const char *name) {
#if defined __APPLE__
    int r;
    if (strcmp(name, A_KAUTH_FILESEC_XATTR) == 0) {
        char new_name[MAXPATHLEN];
        memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
        memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
        r = removexattr(path, new_name, XATTR_NOFOLLOW);
    } else
        r = removexattr(path, name, XATTR_NOFOLLOW);
#else
    int r = lremovexattr(path, name);
#endif
    if (0 == r)
        op1('w', path);
    return 0 == r ? 0 : -errno;
}
#endif /* HAVE_SETXATTR */

#ifdef HAVE_LIBULOCKMGR
static int
fsat_lock(const char *path, struct fuse_file_info *fi, int cmd,
          struct flock *lock) {
    struct fsat_fileh *f = fileh(fi);
    assert(0 <= f->fd);
    return ulockmgr_op(f->fd, cmd, lock, &fi->lock_owner,
                       sizeof(fi->lock_owner));
}
#endif

static int
fsat_flock(const char *path, struct fuse_file_info *fi, int op) {
    int r;
    struct fsat_fileh *f = fileh(fi);
    assert(0 <= f->fd);
    r = flock(f->fd, op);
    return r == 0 ? 0 : -errno;
}

static struct fuse_operations fsat_oper = {
    .getattr = fsat_getattr,
    .fgetattr = fsat_fgetattr,
    .access = fsat_access,
    .readlink = fsat_readlink,
    .opendir = fsat_opendir,
    .readdir = fsat_readdir,
    .releasedir = fsat_releasedir,
    .mknod = fsat_mknod,
    .mkdir = fsat_mkdir,
    .symlink = fsat_symlink,
    .unlink = fsat_unlink,
    .rmdir = fsat_rmdir,
    .rename = fsat_rename,
    .link = fsat_link,
    .chmod = fsat_chmod,
    .chown = fsat_chown,
    .truncate = fsat_truncate,
    .ftruncate = fsat_ftruncate,
#ifdef HAVE_UTIMENSAT
    .utimens = fsat_utimens,
#endif
    .create = fsat_create,
    .open = fsat_open,
    .read = fsat_read,
    .read_buf = fsat_read_buf,
    .write = fsat_write,
    .write_buf = fsat_write_buf,
    .statfs = fsat_statfs,
    .flush = fsat_flush,
    .release = fsat_release,
    .fsync = fsat_fsync,
#ifdef HAVE_POSIX_FALLOCATE
    .fallocate = fsat_fallocate,
#endif
#ifdef HAVE_SETXATTR
    .setxattr = fsat_setxattr,
    .getxattr = fsat_getxattr,
    .listxattr = fsat_listxattr,
    .removexattr = fsat_removexattr,
#endif
#ifdef HAVE_LIBULOCKMGR
    .lock = fsat_lock,
#endif
    .flock = fsat_flock,
    .flag_nopath = 1,
};

static void
usage(const char *nm) {
    fprintf(stderr, "usage: %s [-r rootpid] [-g generator]\n", nm);
    exit(1);
}

static void
opts(int argc, char *argv[]) {
    int ch;
    while ((ch = getopt(argc, argv, "r:g:")) != -1) {
        switch (ch) {
            case 'r':
                s_root = atoi(optarg);
                break;
            case 'g':
                s_generator = optarg;
                break;
            default:
                usage(argv[0]);
        }
    }
}

int
main(int argc, char *argv[]) {
    char *mpt = "traced";
    char *args[] = {argv[0], "-f", mpt};
    opts(argc, argv);
#if defined __linux__
    umount(mpt);
#else
    unmount(mpt, 0);
#endif
    mkdir(mpt, 0755);
    umask(0);
    if (!s_root)
        s_root = getppid();
    return fuse_main(sizeof(args) / sizeof(args[0]), args, &fsat_oper, 0);
}
