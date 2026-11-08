/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "apache-cc-core.h"
#include "apache-cc-log.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __linux__
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static yz_cc_row table[YZ_CC_ROWS], other_site[YZ_CC_ROWS];

static void log_storage(const char *directory)
{
    char path[4096], alias[4096], content[64];
    struct stat st;
    const char event[] = "{\"owned\":true}\n";
    int fd;
    assert(snprintf(path,sizeof(path),"%s/events.log",directory)>0);
    assert(snprintf(alias,sizeof(alias),"%s/alias",directory)>0);
    assert(yz_cc_log_append(path,event,sizeof(event)-1)==0); /* never create */
    fd=open(path,O_CREAT|O_EXCL|O_RDWR,0600);assert(fd>=0);assert(close(fd)==0);
    assert(yz_cc_log_append(path,event,sizeof(event)-1)==1);
    fd=open(path,O_RDONLY);assert(fd>=0);assert(read(fd,content,sizeof(event)-1)==(ssize_t)(sizeof(event)-1));assert(memcmp(content,event,sizeof(event)-1)==0);assert(close(fd)==0);
    assert(symlink(path,alias)==0);assert(yz_cc_log_append(alias,event,sizeof(event)-1)==0);assert(unlink(alias)==0);
    assert(link(path,alias)==0);assert(yz_cc_log_append(path,event,sizeof(event)-1)==0);assert(unlink(alias)==0);
    assert(chmod(path,0640)==0);assert(yz_cc_log_append(path,event,sizeof(event)-1)==0);assert(chmod(path,0600)==0);
    fd=open(path,O_RDWR);assert(fd>=0);assert(write(fd,"unknown",7)==7);assert(ftruncate(fd,7)==0);assert(close(fd)==0);
    assert(yz_cc_log_append(path,event,sizeof(event)-1)==0);assert(stat(path,&st)==0&&st.st_size==7);
    fd=open(path,O_RDWR);assert(fd>=0);assert(ftruncate(fd,YZ_CC_LOG_BYTES)==0);assert(pwrite(fd,"\n",1,YZ_CC_LOG_BYTES-1)==1);assert(close(fd)==0);
    assert(yz_cc_log_append(path,event,sizeof(event)-1)==0);assert(stat(path,&st)==0&&st.st_size==YZ_CC_LOG_BYTES);
    assert(mkfifo(alias,0600)==0);assert(yz_cc_log_append(alias,event,sizeof(event)-1)==0);assert(unlink(alias)==0);
    puts("PASS bounded private log refuses creation, symlinks, hardlinks, FIFO, wrong modes, unknown tails and overflow without changing old bytes");
}

static yz_cc_zone zone(unsigned int key, unsigned int rate, unsigned int burst)
{
    yz_cc_zone z = {{0}, 0, 0};
    /* Deliberate hash collisions exercise the full bounded probe window. */
    z.key[30] = (unsigned char)(key >> 8);
    z.key[31] = (unsigned char)key;
    z.rate = rate; z.burst = burst;
    return z;
}

static void clocks(void)
{
    yz_cc_zone z = zone(1, 7, 3);
    uint64_t retry, start = UINT64_C(10000000000);
    size_t i;
    memset(table, 0, sizeof(table));
    for (i = 0; i < 4; ++i) assert(yz_cc_admit(table, &z, 1, start, &retry) == 1);
    assert(yz_cc_admit(table, &z, 1, start, &retry) == 0 && retry == 142857143);
    assert(yz_cc_admit(table, &z, 1, start + 142857142, &retry) == 0);
    assert(yz_cc_admit(table, &z, 1, start + 142857143, &retry) == 1);
    /* Backwards time neither refills nor moves the origin backwards. */
    assert(yz_cc_admit(table, &z, 1, start - 1, &retry) == 0);
    assert(yz_cc_admit(table, &z, 1, start + 285714285, &retry) == 0);
    assert(yz_cc_admit(table, &z, 1, start + 285714286, &retry) == 1);
    assert(yz_cc_admit(table, &z, 1, UINT64_MAX - 1, &retry) == 1);
    puts("PASS exact fractional refill, no double interval and overflow saturation");
}

static void batch(void)
{
    yz_cc_zone zones[] = {zone(2, 200, 1), zone(3, 1, 1)};
    uint64_t retry, start = UINT64_C(20000000000);
    memset(table, 0, sizeof(table));
    assert(yz_cc_admit(table, zones, 2, start, &retry) == 1);
    assert(yz_cc_admit(table, zones, 2, start, &retry) == 1);
    assert(yz_cc_admit(table, zones, 2, start + 5000000, &retry) == 0);
    /* The URL denial did not consume the freshly refilled site token. */
    assert(yz_cc_admit(table, zones, 1, start + 5000000, &retry) == 1);
    assert(yz_cc_admit(table, zones, 1, start + 5000000, &retry) == 0);
    zones[1] = zones[0];
    assert(yz_cc_admit(table, zones, 2, start + YZ_CC_NS, &retry) == -1);
    assert(yz_cc_admit(table, zones, 1, start + YZ_CC_NS, &retry) == 1);
    assert(yz_cc_admit(table, zones, 1, start + YZ_CC_NS, &retry) == 1);
    assert(yz_cc_admit(table, zones, 1, start + YZ_CC_NS, &retry) == 0);
    puts("PASS multi-zone denial has no partial charge or duplicate-key bypass");
}

static void capacity(void)
{
    unsigned int i;
    uint64_t retry, start = UINT64_C(30000000000);
    yz_cc_zone z;
    memset(table, 0, sizeof(table)); memset(other_site, 0, sizeof(other_site));
    for (i = 0; i < YZ_CC_PROBES; ++i) {
        z = zone(i, 1, 1);
        assert(yz_cc_admit(table, &z, 1, start, &retry) == 1);
    }
    z = zone(YZ_CC_PROBES, 1, 1);
    assert(yz_cc_admit(table, &z, 1, start + YZ_CC_NS - 1, &retry) == -1);
    assert(yz_cc_admit(other_site, &z, 1, start, &retry) == 1);
    assert(yz_cc_admit(table, &z, 1, start + YZ_CC_NS, &retry) == 1);
    assert(yz_cc_admit(table, &z, 1, start + YZ_CC_NS, &retry) == 1);
    assert(yz_cc_admit(table, &z, 1, start + YZ_CC_NS, &retry) == 0);
    puts("PASS bounded capacity preserves active quotas and separate site tables");
}

static void commits(void)
{
    yz_cc_zone z = zone(1, 1, 1);
    uint64_t retry;
    size_t index;
    yz_cc_value before, after;
    unsigned int inactive;
    memset(table, 0, sizeof(table));
    assert(yz_cc_admit(table, &z, 1, 1, &retry) == 1);
    assert(yz_cc_find(table, &z, 1, NULL, 0, &index) == 1);
    before = yz_cc_read(&table[index]);
    inactive = (atomic_load(&table[index].active) ^ 1u) & 1u;
    memset(&table[index].value[inactive], 0xfe, sizeof(yz_cc_value));
    after = yz_cc_read(&table[index]);
    assert(memcmp(&before, &after, sizeof(before)) == 0);
    assert(yz_cc_admit(table, &z, 1, 1, &retry) == 1);
    assert(yz_cc_admit(table, &z, 1, 1, &retry) == 0);
    puts("PASS interrupted inactive-copy write cannot reset a committed quota");
}

#ifdef __linux__
typedef struct { pthread_mutex_t mutex; unsigned int allowed; yz_cc_row rows[YZ_CC_ROWS]; } shared_fixture;
static void processes(void)
{
    shared_fixture *shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    pthread_mutexattr_t attr;
    pid_t children[8], victim;
    unsigned int i, j;
    int status;
    yz_cc_zone z = zone(41, 20, 30);
    uint64_t retry;
    assert(shared != MAP_FAILED);
    memset(shared, 0, sizeof(*shared));
    assert(pthread_mutexattr_init(&attr) == 0);
    assert(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) == 0);
    assert(pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST) == 0);
    assert(pthread_mutex_init(&shared->mutex, &attr) == 0);
    assert(pthread_mutexattr_destroy(&attr) == 0);
    for (i = 0; i < 8; ++i) {
        children[i] = fork(); assert(children[i] >= 0);
        if (children[i] == 0) {
            for (j = 0; j < 400; ++j) {
                assert(pthread_mutex_lock(&shared->mutex) == 0);
                if (yz_cc_admit(shared->rows, &z, 1, YZ_CC_NS, &retry) == 1) shared->allowed++;
                assert(pthread_mutex_unlock(&shared->mutex) == 0);
            }
            _exit(0);
        }
    }
    for (i = 0; i < 8; ++i) { assert(waitpid(children[i], &status, 0) == children[i]); assert(WIFEXITED(status) && WEXITSTATUS(status) == 0); }
    assert(shared->allowed == 31);
    victim = fork(); assert(victim >= 0);
    if (victim == 0) {
        size_t index;
        unsigned int inactive;
        assert(pthread_mutex_lock(&shared->mutex) == 0);
        assert(yz_cc_find(shared->rows, &z, YZ_CC_NS, NULL, 0, &index) == 1);
        inactive = (atomic_load(&shared->rows[index].active) ^ 1u) & 1u;
        memset(&shared->rows[index].value[inactive], 0xfa, sizeof(yz_cc_value));
        (void)kill(getpid(), SIGKILL);
        _exit(99);
    }
    assert(waitpid(victim, &status, 0) == victim && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(pthread_mutex_lock(&shared->mutex) == EOWNERDEAD);
    assert(pthread_mutex_consistent(&shared->mutex) == 0);
    assert(yz_cc_admit(shared->rows, &z, 1, YZ_CC_NS, &retry) == 0);
    assert(pthread_mutex_unlock(&shared->mutex) == 0);
    assert(pthread_mutex_destroy(&shared->mutex) == 0);
    assert(munmap(shared, sizeof(*shared)) == 0);
    puts("PASS 3200 admissions across eight real processes share exactly 31 tokens; SIGKILL owner recovery has no refill");
}
#endif

int main(int argc,char **argv)
{
    assert(argc==2);
    clocks(); batch(); capacity(); commits();
    log_storage(argv[1]);
#ifdef __linux__
    processes();
#endif
    return 0;
}
