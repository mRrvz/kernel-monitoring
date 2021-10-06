#include "hooks.h"

#pragma GCC optimize("-fno-optimize-sibling-calls")

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/* sys_clone */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);

static asmlinkage long hook_sys_clone(struct pt_regs *regs)
{
    ktime_t time;

    time = ktime_get_boottime_seconds();
    /* TODO: atomic operation or spinlock */
    syscalls_time_array[time % TIME_ARRAY_SIZE].p1 |= SYSCLONE_NUM;

    return real_sys_clone(regs);
}
#else
static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
        unsigned long newsp, int __user *parent_tidptr,
        int __user *child_tidptr, unsigned long tls);

static asmlinkage long hook_sys_clone(unsigned long clone_flags,
        unsigned long newsp, int __user *parent_tidptr,
        int __user *child_tidptr, unsigned long tls)
{
    ktime_t time;

    time = ktime_get_boottime_seconds();
    /* TODO: atomic operation or spinlock */
    syscalls_time_array[time % TIME_ARRAY_SIZE].p1 |= SYSCLONE_NUM;

    return real_sys_clone(clone_flags, newsp, parent_tidptr, child_tidptr, tls);
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define ADD_HOOK(_name, _function, _original)   \
{                                               \
    .name = SYSCALL_NAME(_name),                \
    .function = (_function),                    \
    .original = (_original),                    \
}

static struct ftrace_hook hooked_functions[] = {
    ADD_HOOK("sys_clone", hook_sys_clone, &real_sys_clone),
    //HOOK("sys_execve",  fh_sys_execve,  &real_sys_execve),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

    ENTER_LOG();

	if (register_kprobe(&kp) < 0) {
        EXIT_LOG();
        return 0;
    }

	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);

    EXIT_LOG();

	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
    unsigned long retval;

    ENTER_LOG();
	retval = kallsyms_lookup_name(name);
    EXIT_LOG();

    return retval;
}
#endif

static int resolve_hook_address(struct ftrace_hook *hook)
{
    ENTER_LOG();

    if (!(hook->address = lookup_name(hook->name))) {
        pr_debug("unresolved symbol: %s\n", hook->name);
        EXIT_LOG();
        return -ENOENT;
    }

    *((unsigned long*) hook->original) = hook->address;

    EXIT_LOG();

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

    ENTER_LOG();

    if ((rc = resolve_hook_address(hook))) {
        EXIT_LOG();
        return rc;
    }

    /* Callback function. */
    hook->ops.func = ftrace_thunk; 
    /* Save processor registers. */
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    /* Turn of ftrace for our function. */
    if ((rc = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0))) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", rc);
        return rc;
    }

    /* Allow ftrace call our callback. */
    if ((rc = register_ftrace_function(&hook->ops))) {
        pr_debug("register_ftrace_function() failed: %d\n", rc);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    }

    EXIT_LOG();

    return rc;
}

static void remove_hook(struct ftrace_hook *hook) {
    int rc;

    ENTER_LOG();

    if (hook->address == 0x00) {
        EXIT_LOG();
        return;
    }

    if ((rc = unregister_ftrace_function(&hook->ops))) {
        pr_debug("unregister_ftrace_function() failed: %d\n", rc);
    }

    if ((rc = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0))) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", rc);
    }

    hook->address = 0x00;

    EXIT_LOG();
}

int install_hooks(void) {
    size_t i;
    int rc;

    ENTER_LOG();

    for (i = 0; i < ARRAY_SIZE(hooked_functions); i++) {
        if ((rc = install_hook(&hooked_functions[i]))) {
            pr_debug("instal_hooks failed: %d\n", rc);
            goto err;
        }
    }

    EXIT_LOG();

    return 0;

err: 
    while (i != 0) {
        remove_hook(&hooked_functions[--i]);
    }

    EXIT_LOG();

    return rc;
}

void remove_hooks(void) {
    size_t i;

    ENTER_LOG();

    for (i = 0; i < ARRAY_SIZE(hooked_functions); i++) {
        remove_hook(&hooked_functions[i]);
    }

    EXIT_LOG();
}
