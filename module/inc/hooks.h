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

#define HOOK(_name, _function, _original) \
{                                       \
    .name = (_name),                    \
    .function = (_function),            \
    .original = (_original),            \
}

void remove_hooks(struct ftrace_hook hooks[], const size_t cnt);

// sys_clone
static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
        unsigned long newsp, int __user *parent_tidptr,
        int __user *child_tidptr, unsigned long tls);

static asmlinkage long hook_sys_clone(unsigned long clone_flags,
        unsigned long newsp, int __user *parent_tidptr,
        int __user *child_tidptr, unsigned long tls);

#endif
