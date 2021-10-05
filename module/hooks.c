#include "hooks.h"

#pragma GCC optimize("-fno-optimize-sibling-calls")

// `syscalls_time_array` - array that stores the number of calls 
// to each syscall per second of time for the last 24 hours (86400 seconds).
// - Index - second of time. 
// - Value is struct with two 64bit fields; bit is set to 1 - 
// syscall was called this second.

static volatile syscalls_info_t syscalls_time_array[86400];

// sys_clone
static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
        unsigned long newsp, int __user *parent_tidptr,
        int __user *child_tidptr, unsigned long tls);

static asmlinkage long hook_sys_clone(unsigned long clone_flags,
        unsigned long newsp, int __user *parent_tidptr,
        int __user *child_tidptr, unsigned long tls)
{
    long rc;
    ktime_t time;

    time = ktime_get_boottime();
    // TODO: atomic operation or spinlock
    syscalls_time_array[time].p1 |= 0x01;

    rc = real_sys_clone(clone_flags, newsp, parent_tidptr,
        child_tidptr, tls);

    return rc;
}

#define ADD_HOOK(_name, _function, _original)   \
{                                               \
    .name = (_name),                            \
    .function = (_function),                    \
    .original = (_original),                    \
}

static struct ftrace_hook hooked_functions[] = {
    ADD_HOOK("sys_clone", hook_sys_clone, &real_sys_clone),
    //HOOK("sys_execve",  fh_sys_execve,  &real_sys_execve),
};

static int resolve_hook_address(struct ftrace_hook *hook)
{
    if (!(hook->address = kallsyms_lookup_name(hook->name))) {
        pr_debug("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long*) hook->original) = hook->address;

    return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	if (!within_module(parent_ip, THIS_MODULE)) {
		regs->ip = (unsigned long)hook->function;
    }
}

static int install_hook(struct ftrace_hook *hook) {
    int rc;

    if ((rc = resolve_hook_address(hook))) {
        return rc;
    }

    // Callback function.
    hook->ops.func = ftrace_thunk; 
    // Save processor registers.
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_IPMODIFY;

    // Turn of ftrace for our function.
    if ((rc = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0))) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", rc);
        return rc;
    }

    // Allow ftrace call our callback.
    if ((rc = register_ftrace_function(&hook->ops))) {
        pr_debug("register_ftrace_function() failed: %d\n", rc);

        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

        return rc;
    }

    return 0;
}

static void remove_hook(struct ftrace_hook *hook) {
    int rc;

    if ((rc = unregister_ftrace_function(&hook->ops))) {
        pr_debug("unregister_ftrace_function() failed: %d\n", rc);
    }

    if ((rc = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0))) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", rc);
    }
}

int install_hooks(void) {
    size_t i; 
    int rc;

    for (i = 0; i < ARRAY_SIZE(hooked_functions); i++) {
        if ((rc = install_hook(&hooked_functions[i]))) {
            pr_debug("instal_hooks failed: %d\n", rc);
            goto err;
        }
    }

    return 0;

err: 
    while (i != 0) {
        remove_hook(&hooked_functions[--i]);
    }

    return rc;
}

void remove_hooks(void) {
    size_t i;

    for (i = 0; i < ARRAY_SIZE(hooked_functions); i++) {
        remove_hook(&hooked_functions[i]);
    }
}
