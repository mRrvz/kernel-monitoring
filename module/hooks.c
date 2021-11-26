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

ktime_t start_time;
static DEFINE_SPINLOCK(my_lock);

static void inline update_syscall_array(int syscall_num) {
    ktime_t time;

    time = ktime_get_boottime_seconds() - start_time;

    spin_lock(&my_lock);

    if (syscall_num < 64) {
        syscalls_time_array[time % TIME_ARRAY_SIZE].p1 |= 1UL << syscall_num;
    } else {
        syscalls_time_array[time % TIME_ARRAY_SIZE].p2 |= 1UL << (syscall_num % 64);
    }

    spin_unlock(&my_lock);
}

/* 0 - sys_read */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_read)(struct pt_regs *regs);

static asmlinkage long hook_sys_read(struct pt_regs *regs)
{
    update_syscall_array(SYS_READ_NUM);
    return real_sys_read(regs);
}
#else
static asmlinkage long (*real_sys_read)(unsigned int fd, char __user *buf, size_t count);

static asmlinkage long hook_sys_read(unsigned int fd, char __user *buf, size_t count)
{
    update_syscall_array(SYS_READ_NUM);
    return real_sys_read(fd, buf, count);
}
#endif

/* 1 - sys_write */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_write)(struct pt_regs *regs);

static asmlinkage long hook_sys_write(struct pt_regs *regs)
{
    update_syscall_array(SYS_WRITE_NUM);
    return real_sys_write(regs);
}
#else
static asmlinkage long (*real_sys_write)(unsigned int fd, const char __user *buf, size_t count);

static asmlinkage long hook_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
    update_syscall_array(SYS_WRITE_NUM);
    return real_sys_write(fd, buf, count);
}
#endif

/* 2 - sys_open */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_open)(struct pt_regs *regs);

static asmlinkage long hook_sys_open(struct pt_regs *regs)
{
    update_syscall_array(SYS_OPEN_NUM);
    return real_sys_open(regs);
}
#else
static asmlinkage long (*real_sys_open)(const char __user *filename, int flags, umode_t mode);

static asmlinkage long hook_sys_open(const char __user *filename, int flags, umode_t mode);
{
    update_syscall_array(SYS_OPEN_NUM);
    return real_sys_open(filename, flags, mode);
}
#endif

/* 3 - sys_close */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_close)(struct pt_regs *regs);

static asmlinkage long hook_sys_close(struct pt_regs *regs)
{
    update_syscall_array(SYS_CLOSE_NUM);
    return real_sys_close(regs);
}
#else
static asmlinkage long (*real_sys_close)(unsigned int fd);

static asmlinkage long hook_sys_close(unsigned int fd);
{
    update_syscall_array(SYS_CLOSE_NUM);
    return real_sys_close(fd);
}
#endif

/* 9 - sys_mmap */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_mmap)(struct pt_regs *regs);

static asmlinkage long hook_sys_mmap(struct pt_regs *regs)
{
    update_syscall_array(SYS_MMAP_NUM);
    return real_sys_mmap(regs);
}
#else
static asmlinkage long (*real_sys_mmap)(unsigned int fd);

static asmlinkage long hook_sys_mmap(unsigned long addr, unsigned long len,
                                     int prot, int flags,
                                     int fd, long off)
{
    update_syscall_array(SYS_CLOSE_NUM);
    return real_sys_mmap(addr, len, prot, flags, fd, off);
}
#endif

/* 24 - sys_sched_yield */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_sched_yield)(struct pt_regs *regs);

static asmlinkage long hook_sys_sched_yield(struct pt_regs *regs)
{
    update_syscall_array(SYS_SCHED_YIELD_NUM);
    return real_sys_sched_yield(regs);
}
#else
static asmlinkage long (*real_sys_sched_yield)(void);

static asmlinkage long hook_sys_sched_yield(void)
{
    update_syscall_array(SYS_SCHED_YIELD_NUM);
    return real_sys_sched_yield();
}
#endif

/* 41 - sys_socket */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_socket)(struct pt_regs *regs);

static asmlinkage long hook_sys_socket(struct pt_regs *regs)
{
    update_syscall_array(SYS_SOCKET_NUM);
    return real_sys_socket(regs);
}
#else
static asmlinkage long (*real_sys_socket)(int, int, int);

static asmlinkage long hook_sys_socket(int a, int b, int c)
{
    update_syscall_array(SYS_SOCKET_NUM);
    return real_sys_socket(a, b, c);
}
#endif

/* 42 - sys_connect */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_connect)(struct pt_regs *regs);

static asmlinkage long hook_sys_connect(struct pt_regs *regs)
{
    update_syscall_array(SYS_CONNECT_NUM);
    return real_sys_connect(regs);
}
#else
static asmlinkage long (*real_sys_connect)(int, struct sockaddr __user *, int);

static asmlinkage long hook_sys_connect(int a, struct sockaddr __user * b, int c);
{
    update_syscall_array(SYS_CONNECT_NUM);
    return real_sys_connect(a, b, c);
}
#endif

/* 43 - sys_accept */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_accept)(struct pt_regs *regs);

static asmlinkage long hook_sys_accept(struct pt_regs *regs)
{
    update_syscall_array(SYS_ACCEPT_NUM);
    return real_sys_accept(regs);
}
#else
static asmlinkage long (*real_sys_accept)(int, struct sockaddr __user *, int __user *)

static asmlinkage long hook_sys_accept(int a, struct sockaddr __user * b, int __user *c)
{
    update_syscall_array(SYS_ACCEPT_NUM);
    return real_sys_accept(a, b, c);
}
#endif

/* 44 - sys_sendto */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_sendto)(struct pt_regs *regs);

static asmlinkage long hook_sys_sendto(struct pt_regs *regs)
{
    update_syscall_array(SYS_SENDTO_NUM);
    return real_sys_sendto(regs);
}
#else
static asmlinkage long (*real_sys_sendto)(int, void __user *, size_t, unsigned,
                                          struct sockaddr __user *, int);

static asmlinkage long hook_sys_sendto(int a, void __user * b, size_t c, unsigned d,
                                       struct sockaddr __user *e, int f);
{
    update_syscall_array(SYS_SENDTO_NUM);
    return real_sys_sendto(a, b, c, d, e, f);
}
#endif

/* 45 - sys_recvfrom */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_recvfrom)(struct pt_regs *regs);

static asmlinkage long hook_sys_recvfrom(struct pt_regs *regs)
{
    update_syscall_array(SYS_RECVFROM_NUM);
    return real_sys_recvfrom(regs);
}
#else
static asmlinkage long (*real_sys_recvfrom)(int, void __user *, size_t, unsigned,
                                          struct sockaddr __user *, int __user *)

static asmlinkage long hook_sys_recvfrom(int a, void __user *b, size_t c, unsigned d,
                                       struct sockaddr __user * e, int __user *f)
{
    update_syscall_array(SYS_RECVFROM_NUM);
    return real_sys_recvfrom(a, b, c, d, e, f);
}
#endif

/* 46 - sys_sendmsg */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_sendmsg)(struct pt_regs *regs);

static asmlinkage long hook_sys_sendmsg(struct pt_regs *regs)
{
    update_syscall_array(SYS_SENDMSG_NUM);
    return real_sys_sendmsg(regs);
}
#else
static asmlinkage long (*real_sys_sendmsg)(int fd, struct user_msghdr __user *msg, unsigned flags);

static asmlinkage long hook_sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags)
{
    update_syscall_array(SYS_SENDMSG_NUM);
    return real_sys_sendmsg(fd, msg, flags);
}
#endif

/* 47 - sys_recvmsg */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_recvmsg)(struct pt_regs *regs);

static asmlinkage long hook_sys_recvmsg(struct pt_regs *regs)
{
    update_syscall_array(SYS_RECVMSG_NUM);
    return real_sys_recvmsg(regs);
}
#else
static asmlinkage long (*real_sys_recvmsg)(int fd, struct user_msghdr __user *msg, unsigned flags);

static asmlinkage long hook_sys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags)
{
    update_syscall_array(SYS_RECVMSG_NUM);
    return real_sys_recvmsg(fd, msg, flags);
}
#endif

/* 48 - sys_shutdown */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_shutdown)(struct pt_regs *regs);

static asmlinkage long hook_sys_shutdown(struct pt_regs *regs)
{
    update_syscall_array(SYS_SHUTDOWN_NUM);
    return real_sys_shutdown(regs);
}
#else
static asmlinkage long (*real_sys_shutdown)(int, int);

static asmlinkage long hook_sys_shutdown(int t, int m)
{
    update_syscall_array(SYS_SHUTDOWN_NUM);
    return real_sys_shutdown(t, m);
}
#endif

/* 56 - sys_clone */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);

static asmlinkage long hook_sys_clone(struct pt_regs *regs)
{
    update_syscall_array(SYS_CLONE_NUM);
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
    update_syscall_array(SYS_CLONE_NUM);
    return real_sys_clone(clone_flags, newsp, parent_tidptr, child_tidptr, tls);
}
#endif

/* 59 - sys_execve */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long hook_sys_execve(struct pt_regs *regs)
{
    update_syscall_array(SYS_EXECVE_NUM);
    return real_sys_execve(regs);
}
#else
static asmlinkage long (*real_sys_execve)(const char __user *filename,
        const char __user *const __user *argv,
        const char __user *const __user *envp);

static asmlinkage long hook_sys_execve(const char __user *filename,
        const char __user *const __user *argv,
        const char __user *const __user *envp)
{
    update_syscall_array(SYS_EXECVE_NUM);
    return real_sys_execve(filename, argv, envp);
}
#endif

/* 83 - sys_mkdir */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_mkdir)(struct pt_regs *regs);

static asmlinkage long hook_sys_mkdir(struct pt_regs *regs)
{
    update_syscall_array(SYS_MKDIR_NUM);
    return real_sys_mkdir(regs);
}
#else
static asmlinkage long (*real_sys_mkdir)(const char __user *pathname, umode_t mode);

static asmlinkage long hook_sys_mkdir(const char __user *pathname, umode_t mode);
{
    update_syscall_array(SYS_MKDIR_NUM);
    return real_sys_mkdir(pathname, mode);
}
#endif

/* 84 - sys_rmdir */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_rmdir)(struct pt_regs *regs);

static asmlinkage long hook_sys_rmdir(struct pt_regs *regs)
{
    update_syscall_array(SYS_RMDIR_NUM);
    return real_sys_rmdir(regs);
}
#else
static asmlinkage long (*real_sys_rmdir)(const char __user *pathname);

static asmlinkage long hook_sys_rmdir(const char __user *pathname);
{
    update_syscall_array(SYS_RMDIR_NUM);
    return real_sys_rmdir(pathname);
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
    ADD_HOOK("sys_execve",  hook_sys_execve,  &real_sys_execve),
    ADD_HOOK("sys_write",  hook_sys_write,  &real_sys_write),
    ADD_HOOK("sys_open",  hook_sys_open,  &real_sys_open),
    ADD_HOOK("sys_close",  hook_sys_close,  &real_sys_close),
    ADD_HOOK("sys_mmap",  hook_sys_mmap,  &real_sys_mmap),
    ADD_HOOK("sys_sched_yield",  hook_sys_sched_yield,  &real_sys_sched_yield),
    ADD_HOOK("sys_socket",  hook_sys_socket,  &real_sys_socket),
    ADD_HOOK("sys_connect",  hook_sys_connect,  &real_sys_connect),
    ADD_HOOK("sys_accept",  hook_sys_accept,  &real_sys_accept),
    ADD_HOOK("sys_sendto",  hook_sys_sendto,  &real_sys_sendto),
    ADD_HOOK("sys_recvfrom",  hook_sys_recvfrom,  &real_sys_recvfrom),
    ADD_HOOK("sys_sendmsg",  hook_sys_sendmsg,  &real_sys_sendmsg),
    ADD_HOOK("sys_recvmsg",  hook_sys_recvmsg,  &real_sys_recvmsg),
    ADD_HOOK("sys_shutdown",  hook_sys_shutdown,  &real_sys_shutdown),
    ADD_HOOK("sys_read", hook_sys_read, &real_sys_read),
    ADD_HOOK("sys_clone", hook_sys_clone, &real_sys_clone),
    ADD_HOOK("sys_mkdir", hook_sys_mkdir, &real_sys_mkdir),
    ADD_HOOK("sys_rmdir", hook_sys_rmdir, &real_sys_rmdir),
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
