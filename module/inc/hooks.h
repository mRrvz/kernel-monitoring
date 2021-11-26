#ifndef __HOOKS_H_
#define __HOOKS_H_

#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/ftrace.h>
#include <linux/time.h>

#include "log.h"

#define SYS_READ_NUM 0
#define SYS_WRITE_NUM 1
#define SYS_OPEN_NUM 2
#define SYS_CLOSE_NUM 3

#define SYS_MMAP_NUM 9

#define SYS_SCHED_YIELD_NUM 24

#define SYS_SOCKET_NUM 41
#define SYS_CONNECT_NUM 42
#define SYS_ACCEPT_NUM 43
#define SYS_SENDTO_NUM 44
#define SYS_RECVFROM_NUM 45
#define SYS_SENDMSG_NUM 46
#define SYS_RECVMSG_NUM 47
#define SYS_SHUTDOWN_NUM 48

#define SYS_CLONE_NUM 56
#define SYS_EXECVE_NUM 59

#define SYS_MKDIR_NUM 83
#define SYS_RMDIR_NUM 84

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

typedef struct {
    uint64_t p1;
    uint64_t p2;
} syscalls_info_t;

/* `syscalls_time_array` - array that stores the number of calls
 * to each syscall per second of time for the last 24 hours (86400 seconds).
 * - Index - second of time.
 * - Value is struct with two 64bit fields; bit is set to 1 -
 * syscall was called this second.
 */

#define TIME_ARRAY_SIZE 86400
extern syscalls_info_t syscalls_time_array[TIME_ARRAY_SIZE];

void remove_hooks(void);
int install_hooks(void);

#endif
