#ifndef __HOOKS_H_
#define __HOOKS_H_

#include <linux/ftrace.h>
#include <linux/time.h>

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

void remove_hooks(void);
int install_hooks(void);
int get_exec_stat_calls(void);

#endif
