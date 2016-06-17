#define FUSE_USE_VERSION 29

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

#include "types.h"
#include "ppid.h"
#include "toplevel.h"
#include "op.h"

static const char *s_generator = 0;

struct dirh {
    DIR *dp;
    struct toplevel *tl;
    struct dirent *entry;
    off_t offset;
    char path[PATH_MAX];
    char reported[OP_MAX];
};

struct fileh {
    struct toplevel *tl;
    int fd;
    char path[PATH_MAX];
    char reported[OP_MAX];
};

struct toplevel *
lookup_toplevel() {
    struct fuse_context *ctx = fuse_get_context();
    if (!ctx->private_data)
        ctx->private_data = toplevel_lookup_create(ctx->pid);
    return ctx->private_data;
}

static uintptr_t
fillfh(struct fileh *f, const char *path, int fd, struct toplevel *tl) {
    f->fd = fd;
    f->tl = tl;
    strncpy(f->path, path, PATH_MAX);
    f->path[PATH_MAX - 1] = 0;
    bzero(f->reported, sizeof(f->reported));
    return (uintptr_t)f;
}

static uintptr_t
filldh(struct dirh *d, const char *path, DIR *dp, struct toplevel *tl) {
    d->dp = dp;
    d->tl = tl;
    d->offset = 0;
    d->entry = 0;
    strncpy(d->path, path, PATH_MAX);
    d->path[PATH_MAX - 1] = 0;
    bzero(d->reported, sizeof(d->reported));
    return (uintptr_t)d;
}

static inline struct dirh *
get_dirh(struct fuse_file_info *fi) {
    return (struct dirh *)(uintptr_t)fi->fh;
}

static inline struct fileh *
get_fileh(struct fuse_file_info *fi) {
    return (struct fileh *)(uintptr_t)fi->fh;
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
op2(enum op op, const char *p1, const char *p2) {
    struct toplevel *tl = lookup_toplevel();
    op_register(tl, op, p1, p2);
}

static void
op1(enum op op, const char *p1) {
    op2(op, p1, 0);
}

static void
sop1(enum op op, char *reported, const char *p1) {
    if (!reported[op]) {
        op1(op, p1);
        reported[op] = 1;
    }
}

static void
fop1(struct fileh *f, enum op op) {
    sop1(op, f->reported, f->path);
}

static void
dop1(struct dirh *d, enum op op) {
    sop1(op, d->reported, d->path);
}

static const char *s_ops = "/.ops";
static const int s_opslen = 5;
static const char *s_rootpid = "/.rootpid-";
static const int s_rootpidlen = 10;

static int
is_ops(const char *path) {
    return 0 == strncmp(path, s_ops, s_opslen);
}

static int
is_rootpid(const char *path) {
    return 0 == strncmp(path, s_rootpid, s_rootpidlen);
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
        char buf[2 * PATH_MAX + 32];
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
        struct toplevel *tl = toplevel_lookup(pid);
        if (tl) {
            stat_toplevel(tl, st);
            r = 0;
        } else {
            errno = ENOENT;
            r = -1;
        }
    }
    return r;
}

static int
getattr_cb(const char *path, struct stat *st) {
    int r;
    if (is_ops(path))
        r = stat_ops(path, st);
    else if (is_rootpid(path)) {
        toplevel_set_root(atoi(path + s_rootpidlen));
        r = -1;
        errno = ENOENT;
    } else
        r = lstat(path, st);
    if (0 == r)
        op1(OP_QUERY, path);
    else if (generate(path))
        r = -getattr_cb(path, st);
    return 0 == r ? 0 : -errno;
}

static int
fgetattr_cb(const char *path, struct stat *st, struct fuse_file_info *fi) {
    struct fileh *f = get_fileh(fi);
    int r;
    if (0 <= f->fd)
        r = fstat(f->fd, st);
    else
        r = stat_toplevel(f->tl, st);
    if (0 == r)
        fop1(f, OP_QUERY);
    else if (generate(path))
        r = -fgetattr_cb(path, st, fi);
    return 0 == r ? 0 : -errno;
}

static int
access_cb(const char *path, int mask) {
    int r;
    if (is_ops(path))
        r = 0;
    else if (is_rootpid(path)) {
        toplevel_set_root(atoi(path + s_rootpidlen));
        r = -1;
        errno = ENOENT;
    } else
        r = access(path, mask);
    if (0 == r)
        op1(OP_QUERY, path);
    else if (generate(path))
        r = -access_cb(path, mask);
    return 0 == r ? 0 : -errno;
}

static int
readlink_cb(const char *path, char *buf, size_t size) {
    int r;
    r = readlink(path, buf, size - 1);
    if (0 <= r) {
        buf[r] = '\0';
        op1(OP_READ, path);
    } else if (generate(path))
        r = -readlink_cb(path, buf, size);
    return 0 <= r ? 0 : -errno;
}

static int
opendir_cb(const char *path, struct fuse_file_info *fi) {
    DIR *dp = 0;
    struct toplevel *tl = 0;
    int r;
    if (is_ops(path)) {
        tl = g_toplevel;
        fi->direct_io = 1;
    } else
        dp = opendir(path);
    if (tl || dp) {
        struct dirh *d = malloc(sizeof(*d));
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
readdir_cb(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
           struct fuse_file_info *fi) {
    struct dirh *d = get_dirh(fi);

    if (d->tl) {
        unsigned i;
        for (i = 0; i < MAX_TOPLEVEL; i++) {
            struct toplevel *tl = g_toplevel + i;
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
        dop1(d, OP_LIST);
    }
    return 0;
}

static int
releasedir_cb(const char *path, struct fuse_file_info *fi) {
    struct dirh *d = get_dirh(fi);
    if (d->dp)
        closedir(d->dp);
    free(d);
    return 0;
}

static int
mknod_cb(const char *path, mode_t mode, dev_t rdev) {
    int r;
    if (S_ISFIFO(mode))
        r = mkfifo(path, mode);
    else
        r = mknod(path, mode, rdev);
    if (0 == r)
        op1(OP_WRITE, path);
    return 0 == r ? 0 : -errno;
}

static int
mkdir_cb(const char *path, mode_t mode) {
    int r = mkdir(path, mode);
    if (0 == r)
        op1(OP_WRITE, path);
    return 0 == r ? 0 : -errno;
}

static int
unlink_cb(const char *path) {
    int r = unlink(path);
    if (0 == r)
        op1(OP_DELETE, path);
    return 0 == r ? 0 : -errno;
}

static int
rmdir_cb(const char *path) {
    int r = rmdir(path);
    if (0 == r)
        op1(OP_DELETE, path);
    return 0 == r ? 0 : -errno;
}

static int
symlink_cb(const char *from, const char *to) {
    int r = symlink(from, to);
    if (0 == r)
        op2(OP_LINK, to, from);
    return 0 == r ? 0 : -errno;
}

static int
rename_cb(const char *from, const char *to) {
    int r = rename(from, to);
    if (0 == r)
        op2(OP_RENAME, to, from);
    return 0 == r ? 0 : -errno;
}

static int
link_cb(const char *from, const char *to) {
    int r = link(from, to);
    if (0 == r)
        op2(OP_LINK, to, from);
    return 0 == r ? 0 : -errno;
}

static int
chmod_cb(const char *path, mode_t mode) {
    int r = chmod(path, mode);
    if (0 == r)
        op1(OP_WRITE, path);
    return 0 == r ? 0 : -errno;
}

static int
chown_cb(const char *path, uid_t uid, gid_t gid) {
    int r = lchown(path, uid, gid);
    if (0 == r)
        op1(OP_WRITE, path);
    return 0 == r ? 0 : -errno;
}

static int
truncate_cb(const char *path, off_t size) {
    int r = truncate(path, size);
    if (0 == r)
        op1(OP_WRITE, path);
    return 0 == r ? 0 : -errno;
}

static int
ftruncate_cb(const char *path, off_t size, struct fuse_file_info *fi) {
    int r;
    struct fileh *f = get_fileh(fi);
    if (0 <= f->fd)
        r = ftruncate(f->fd, size);
    else {
        errno = ENOENT;
        r = -1;
    }
    if (0 == r)
        fop1(f, OP_WRITE);
    return 0 == r ? 0 : -errno;
}

static int
utimens_cb(const char *path, const struct timespec ts[2]) {
#ifdef HAVE_UTIMENSAT
    int r = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
#else
    struct utimbuf buf;
    buf.actime = ts[0].tv_sec;
    buf.modtime = ts[1].tv_sec;
    int r = utime(path, &buf);
#endif
    if (0 == r)
        op1(OP_WRITE, path);
    return 0 == r ? 0 : -errno;
}

static int
create_cb(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int fd;
    struct fileh *f;
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
//        fi->direct_io = 1;
#if defined __APPLE__
        fi->purge_ubc = 1;
#endif
        fi->fh = fillfh(f, path, fd, 0);
        fop1(f, OP_WRITE);
    }
    return r;
}

static struct toplevel *
open_ops(const char *path) {
    int pid = ops_pid(path);
    struct toplevel *tl = toplevel_lookup(pid);
    if (!tl)
        errno = -ENOENT;
    return tl;
}

static int
open_cb(const char *path, struct fuse_file_info *fi) {
    struct fileh *f;
    struct toplevel *tl;
    int fd = -1;
    int r = 0;
    if (is_ops(path)) {
        tl = open_ops(path);
        fd = -1;
        fi->direct_io = 1;
    } else if (is_rootpid(path)) {
        toplevel_set_root(atoi(path + s_rootpidlen));
        fd = -1;
        tl = 0;
        errno = ENOENT;
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
    if (!r) {
//        fi->direct_io = 1;
#if defined __APPLE__
        fi->purge_ubc = 1;
#endif
        fi->fh = fillfh(f, path, fd, tl);
    }
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
read_cb(const char *path, char *buf, size_t size, off_t offset,
        struct fuse_file_info *fi) {
    int r;
    struct fileh *f = get_fileh(fi);
    if (0 <= f->fd)
        r = pread(f->fd, buf, size, offset);
    else
        r = read_ops(f->tl, buf, size, offset);
    if (0 <= r)
        fop1(f, OP_READ);
    return 0 <= r ? r : -errno;
}

static int
write_cb(const char *path, const char *buf, size_t size, off_t offset,
         struct fuse_file_info *fi) {
    int r;
    struct fileh *f = get_fileh(fi);
    if (0 <= f->fd)
        r = pwrite(f->fd, buf, size, offset);
    else {
        errno = ENOENT;
        r = -1;
    }
    if (0 <= r)
        fop1(f, OP_WRITE);
    return 0 <= r ? r : -errno;
}

#if FUSE_MAKE_VERSION(2, 9) <= FUSE_VERSION
static int
read_buf_cb(const char *path, struct fuse_bufvec **bufp, size_t size,
            off_t offset, struct fuse_file_info *fi) {
    struct fuse_bufvec *src;
    struct fuse_buf *b = 0;
    struct fileh *f = get_fileh(fi);
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
        r = -posix_memalign(&b->mem, getpagesize(), sz);
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
        r = sz;
        fop1(f, OP_READ);
    }
    return r;
}

static int
write_buf_cb(const char *path, struct fuse_bufvec *buf, off_t offset,
             struct fuse_file_info *fi) {
    struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));
    struct fuse_buf *b = dst.buf;
    struct fileh *f = get_fileh(fi);
    int r;
    assert(0 <= f->fd);
    if (0 <= f->fd) {
        b->flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
        b->fd = f->fd;
        b->pos = offset;
        fop1(f, OP_WRITE);
        r = fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
    } else
        r = -ENOENT;
    return r;
}

static int
flock_cb(const char *path, struct fuse_file_info *fi, int op) {
    int r;
    struct fileh *f = get_fileh(fi);
    assert(0 <= f->fd);
    r = flock(f->fd, op);
    return r == 0 ? 0 : -errno;
}

#endif

static int
statfs_cb(const char *path, struct statvfs *stbuf) {
    int r = statvfs(path, stbuf);
    return r == 0 ? 0 : -errno;
}

static int
flush_cb(const char *path, struct fuse_file_info *fi) {
    int r;
    struct fileh *f = get_fileh(fi);
    if (0 <= f->fd)
        r = close(dup(f->fd));
    else
        r = 0;
    return r == 0 ? 0 : -errno;
}

static int
release_cb(const char *path, struct fuse_file_info *fi) {
    struct fileh *f = get_fileh(fi);
    if (0 <= f->fd)
        close(f->fd);
    free(f);
    return 0;
}

static int
fsync_cb(const char *path, int isdatasync, struct fuse_file_info *fi) {
    int r;
    struct fileh *f = get_fileh(fi);
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
fallocate_cb(const char *path, int mode, off_t offset, off_t length,
             struct fuse_file_info *fi) {
    struct fileh *f = get_fileh(fi);
    int r;
    assert(0 <= f->fd);
    if (mode)
        r = EOPNOTSUPP;
    else
        r = posix_fallocate(f->fd, offset, length);
    if (0 == r)
        fop1(f, OP_WRITE);
    return 0 == r ? 0 : -r;
}
#endif

#ifdef HAVE_SETXATTR
static int
setxattr_cb(const char *path, const char *name, const char *value, size_t size,
            int flags
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
        op1(OP_WRITE, path);
    return 0 == r ? 0 : -errno;
}

static int
getxattr_cb(const char *path, const char *name, char *value, size_t size
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
        op1(OP_QUERY, path);
    return 0 <= r ? r : -errno;
}

static int
listxattr_cb(const char *path, char *list, size_t size) {
#if defined __APPLE__
    ssize_t r = listxattr(path, list, size, XATTR_NOFOLLOW);
    if (0 < r) {
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
        op1(OP_QUERY, path);
    return 0 <= r ? r : -errno;
}

static int
removexattr_cb(const char *path, const char *name) {
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
        op1(OP_WRITE, path);
    return 0 == r ? 0 : -errno;
}
#endif /* HAVE_SETXATTR */

#ifdef HAVE_LIBULOCKMGR
static int
lock_cb(const char *path, struct fuse_file_info *fi, int cmd,
        struct flock *lock) {
    struct fileh *f = get_fileh(fi);
    assert(0 <= f->fd);
    return ulockmgr_op(f->fd, cmd, lock, &fi->lock_owner,
                       sizeof(fi->lock_owner));
}
#endif

static struct fuse_operations oper = {
    .getattr = getattr_cb,
    .fgetattr = fgetattr_cb,
    .access = access_cb,
    .readlink = readlink_cb,
    .opendir = opendir_cb,
    .readdir = readdir_cb,
    .releasedir = releasedir_cb,
    .mknod = mknod_cb,
    .mkdir = mkdir_cb,
    .symlink = symlink_cb,
    .unlink = unlink_cb,
    .rmdir = rmdir_cb,
    .rename = rename_cb,
    .link = link_cb,
    .chmod = chmod_cb,
    .chown = chown_cb,
    .truncate = truncate_cb,
    .ftruncate = ftruncate_cb,
    .utimens = utimens_cb,
    .create = create_cb,
    .open = open_cb,
    .read = read_cb,
    .write = write_cb,
    .statfs = statfs_cb,
    .flush = flush_cb,
    .release = release_cb,
    .fsync = fsync_cb,
#ifdef HAVE_POSIX_FALLOCATE
    .fallocate = fallocate_cb,
#endif
#ifdef HAVE_SETXATTR
    .setxattr = setxattr_cb,
    .getxattr = getxattr_cb,
    .listxattr = listxattr_cb,
    .removexattr = removexattr_cb,
#endif
#ifdef HAVE_LIBULOCKMGR
    .lock = lock_cb,
#endif
#if FUSE_MAKE_VERSION(2, 9) <= FUSE_VERSION
    .read_buf = read_buf_cb,
    .write_buf = write_buf_cb,
    .flock = flock_cb,
    .flag_nopath = 1,
#endif
};

/*
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

static void
unmount_prev(const char *mpt) {
#if defined __linux__
    char cmd[PATH_MAX + 32];
    snprintf(cmd, sizeof(cmd), "fusermount -u '%s'", mpt);
    system(cmd);
#else
    unmount(mpt, 0);
#endif
}
*/

int
main(int argc, char *argv[]) {
    char *args[64];
    int nargs = argc;
    assert(argc < sizeof(args) / sizeof(args[0]));
    memcpy(args, argv, nargs * sizeof(args[0]));
    //    args[nargs++] = "-o";
    //    args[nargs++] = "noubc";
    // args[nargs++] = mpt;
    //    opts(argc, argv);
    // unmount_prev(mpt);
    // mkdir(mpt, 0700);
    umask(0);
    return fuse_main(nargs, args, &oper, 0);
}
