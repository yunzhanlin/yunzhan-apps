/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 YunZhan contributors.
 * This private NFSv4 daemon uses an explicit port. It must never unregister
 * or replace another server's mappings in the host's rpcbind service.
 * These functions isolate external portmapper side effects, not NFS dispatch.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>

struct netconfig;
struct netbuf;
int rpcb_unset(uint32_t program, uint32_t version,
               const struct netconfig *configuration) {
    (void)configuration;
    return program == 100003 && version == 4;
}
int rpcb_set(uint32_t program, uint32_t version,
             const struct netconfig *configuration, const struct netbuf *address) {
    (void)configuration;
    (void)address;
    return program == 100003 && version == 4;
}

static int portmapper_address(const struct sockaddr *address, socklen_t length) {
    if (!address || length < sizeof(address->sa_family)) return 0;
    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in))
        return ((const struct sockaddr_in *)address)->sin_port == htons(111);
    if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6))
        return ((const struct sockaddr_in6 *)address)->sin6_port == htons(111);
    if (address->sa_family == AF_UNIX && length > sizeof(sa_family_t)) {
        const struct sockaddr_un *local = (const struct sockaddr_un *)address;
        size_t available = length - sizeof(sa_family_t);
        if (available > sizeof(local->sun_path)) available = sizeof(local->sun_path);
        const char *paths[] = {"/run/rpcbind.sock", "/var/run/rpcbind.sock"};
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            size_t n = strlen(paths[i]);
            if (available >= n && !memcmp(local->sun_path, paths[i], n)
                && (available == n || local->sun_path[n] == '\0')) return 1;
        }
    }
    return 0;
}

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (portmapper_address(address, length)) { errno = EPERM; return -1; }
    return (int)syscall(SYS_connect, fd, address, length);
}
ssize_t sendto(int fd, const void *buffer, size_t length, int flags,
               const struct sockaddr *address, socklen_t address_length) {
    if (portmapper_address(address, address_length)) { errno = EPERM; return -1; }
    return (ssize_t)syscall(SYS_sendto, fd, buffer, length, flags, address, address_length);
}
ssize_t sendmsg(int fd, const struct msghdr *message, int flags) {
    if (message && portmapper_address(message->msg_name, message->msg_namelen)) {
        errno = EPERM; return -1;
    }
    return (ssize_t)syscall(SYS_sendmsg, fd, message, flags);
}
