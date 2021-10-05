#ifndef __HOOKS_H_
#define __HOOKS_H_

#include <linux/ftrace.h>

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

void remove_hooks(void);
int install_hooks(void);
int get_exec_stat_calls(void);

#endif
