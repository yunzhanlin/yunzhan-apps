/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Yunzhan contributors.
 * Bounded, best-effort append to an existing private regular event file.
 * No creation, replacement, automatic rotation, or removal of old evidence.
 */
#ifndef YUNZHAN_APACHE_CC_ROTATION_LOG_H
#define YUNZHAN_APACHE_CC_ROTATION_LOG_H

#include <fcntl.h>
#include <stddef.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define YZ_CC_LOG_BYTES ((off_t)32 * 1024 * 1024)
#define YZ_CC_LOG_LINE 4096u

static int yz_cc_log_append(const char *path, const char *line, size_t length)
{
    struct stat before, after, named;
    ssize_t written;
    char tail;
    int fd, ok = 0;
    if (!path || !line || length == 0 || length > YZ_CC_LOG_LINE || line[length - 1] != '\n') return 0;
    fd = open(path, O_RDWR | O_APPEND | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    /* Each append opens an independent description, so flock also serializes
     * sibling threads and forked workers. An inherited shared descriptor
     * would not provide that exclusion. Logging never waits for this lock. */
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) goto done;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        (before.st_mode & 07777) != 0600 || before.st_nlink != 1 ||
        before.st_uid != geteuid() || before.st_gid != getegid() || before.st_size < 0 ||
        before.st_size > YZ_CC_LOG_BYTES - (off_t)length) goto done;
    /* A process can be suspended after open(), before flock(). Root may
     * exchange the active name while that process is asleep. Never append
     * through that stale description to an already sealed archive. Root's
     * rotation takes this same inode lock for the complete name exchange. */
    if (lstat(path, &named) != 0 || !S_ISREG(named.st_mode) ||
        named.st_dev != before.st_dev || named.st_ino != before.st_ino ||
        named.st_uid != before.st_uid || named.st_gid != before.st_gid ||
        (named.st_mode & 07777) != 0600 || named.st_nlink != 1) goto done;
    /* Preserve an incomplete previous outcome. Never concatenate a new event
     * onto an unknown tail or repair another writer's bytes. */
    if (before.st_size && (pread(fd, &tail, 1, before.st_size - 1) != 1 || tail != '\n')) goto done;
    written = write(fd, line, length);
    if (written == (ssize_t)length) { ok = 1; goto done; }
    /* Roll back only this call's known partial suffix while still holding its
     * exclusive lock. An intervening noncooperating writer is never truncated.
     * A killed process can leave a tail; later appends refuse it above. */
    if (written > 0 && fstat(fd, &after) == 0 && after.st_dev == before.st_dev &&
        after.st_ino == before.st_ino && after.st_size == before.st_size + written) {
        if (ftruncate(fd, before.st_size) != 0) goto done;
    }
done:
    (void)close(fd);
    return ok;
}

#endif
