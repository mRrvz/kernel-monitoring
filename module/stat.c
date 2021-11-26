#include "stat.h"

#define TASK_STATE_FIELD state
#define TASK_STATE_SPEC "%ld"

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,13,0)
#define TASK_STATE_FIELD __state
#define TASK_STATE_SPEC "%d"
#endif

static inline long convert_to_kb(const long n) {
    return n << (PAGE_SHIFT - 10);
}

void print_memory_statistics(struct seq_file *m) {
    struct sysinfo i;

    ENTER_LOG();

    si_meminfo(&i);

    show_int_message(m, "Memory total: %ld kB\n", convert_to_kb(i.totalram));
    show_int_message(m, "Free memory: %ld kB\n", convert_to_kb(i.freeram));
    show_int_message(m, "Available memory: %ld kB\n", convert_to_kb(si_mem_available()));

    EXIT_LOG();
}

void print_task_statistics(struct seq_file *m) {
    struct task_struct *task;
    int total = 0, running = 0, stopped = 0, zombie = 0, interruptible = 0, uninterruptible;

    ENTER_LOG();

    for_each_process(task) {
        switch (task->TASK_STATE_FIELD) {
            case TASK_RUNNING:
                running++;
                break;
            case TASK_INTERRUPTIBLE:
                interruptible++;
                break;
            case TASK_IDLE: /* (TASK_UNINTERRUPTIBLE | TASK_NOLOAD) */
                uninterruptible++;
                break;
            case TASK_STOPPED:
                stopped++;
                break;
            case TASK_TRACED: /* (TASK_WAKEKILL | __TASK_TRACED) */
                stopped++;
                break;
            default:
                printk(KERN_INFO "%x %s %d\n", task->TASK_STATE_FIELD, task->comm, task->pid);
        }

        if (task->exit_state == EXIT_ZOMBIE)
        {
            zombie++;
        }

        total++;
    }

    show_int_message(m, "Total processes: %d\n", total);
    show_int_message(m, "Running: %d\n", running);
    show_int_message(m, "Sleeping: %d ", total - running - stopped - zombie);
    show_int_message(m, "[Interruptible: %d | ", interruptible);
    show_int_message(m, "Uninterruptible: %d]\n", uninterruptible);
    show_int_message(m, "Stopped: %d\n", stopped);
    show_int_message(m, "Zombie: %d\n", zombie);

    EXIT_LOG();
}

syscalls_info_t syscalls_time_array[TIME_ARRAY_SIZE];

static const char *syscalls_names[] = {
    "sys_read", /* 0 */
    "sys_write", 
    "sys_open",
    "sys_close",
    "sys_newstat", /* 4 */
    "sys_newfstat",
    "sys_newlstat",
    "sys_poll",
    "sys_lseek",
    "sys_mmap", /* 9 */
    "sys_mprotect",
    "sys_munmap",
    "sys_brk",
    "sys_rt_sigaction",
    "sys_rt_sigprocmask", /* 14 */
    "stub_rt_sigreturn",
    "sys_ioctl",
    "sys_pread64",
    "sys_pwrite64",
    "sys_readv", /* 19 */
    "sys_writev",
    "sys_access",
    "sys_pipe",
    "sys_select",
    "sys_sched_yield", /* 24 */
    "sys_mremap",
    "sys_msync",
    "sys_mincore",
    "sys_madvise",
    "sys_shmget", /* 29 */
    "sys_shmat",
    "sys_shmctl",
    "sys_dup",
    "sys_dup2",
    "sys_pause", /* 34 */
    "sys_nanosleep",
    "sys_gettimer",
    "sys_alarm",
    "sys_settimer",
    "sys_getpid", /* 39 */
    "sys_sendfile64",
    "sys_socket",
    "sys_connect",
    "sys_accept",
    "sys_sendto", /* 44 */
    "sys_recvfrom",
    "sys_sendmsg",
    "sys_recvmsg",
    "sys_shutdown",
    "sys_bind", /* 49 */
    "sys_listen",
    "sys_getsockname",
    "sys_getpeername",
    "sys_socketpair",
    "sys_setsockopt", /* 54 */
    "sys_getsockopt",
    "sys_clone",
    "sys_fork",
    "sys_vfork",
    "sys_execve", /* 59 */
    "sys_exit",
    "sys_wait4",
    "sys_kill",
    "sys_newuname",
    "sys_semget", /* 64 */
    "sys_semop",
    "sys_semctl",
    "sys_shmdt",
    "sys_msgget",
    "sys_msgsnd", /* 69 */
    "sys_msgrcv",
    "sys_msgctl",
    "sys_fcntl",
    "sys_flock",
    "sys_fsync", /* 74 */
    "sys_fdatasync",
    "sys_truncate",
    "sys_ftruncate",
    "sys_getdents",
    "sys_getcwd", /* 79 */
    "sys_chdir",
    "sys_fchdir",
    "sys_rename",
    "sys_mkdir",
    "sys_rmdir", /* 84 */
    "sys_creat",
    "sys_link",
    "sys_unlink",
    "sys_symlink",
    "sys_readlink", /* 89 */
    "sys_chmod",
    "sys_fchmod",
    "sys_chown",
    "sys_fchown",
    "sys_lchown", /* 94 */
    "sys_umask",
    "sysgettimeofday",
    "sys_getrlimit",
    "sys_getrusage",
    "sys_sysinfo", /* 99 */
    "sys_times",
    "sys_ptrace",
    "sys_getuid",
    "sys_syslog",
    "sys_getgid", /* 104 */
    "sys_setuid",
    "sys_setgid",
    "sys_geteuid",
    "sys_getegid",
    "sys_getpgid", /* 109 */
    "sys_getppid",
    "sys_getpgrp",
    "sys_setsid",
    "sys_setreuid",
    "sys_setregid", /* 114 */
    "sys_getgroups",
    "sys_setgroups",
    "sys_setresuid",
    "sys_getresuid",
    "sys_setresgid", /* 119 */
    "sys_getresgid",
    "sys_getpgid",
    "sys_setfsuid",
    "sys_setfsgid",
    "sys_getsid", /* 124 */
    "sys_capget",  
    "sys_capset",
    "sys_rt_sigpending", /* 127 */
};

static inline void walk_bits_and_find_syscalls(struct seq_file *m, uint64_t num, int syscalls_arr_cnt[]) {
    int i;

    for (i = 0; i < 64; i++) {
        if (num & (1UL << i)) {
            syscalls_arr_cnt[i]++;
        }
    }
}

void print_syscall_statistics(struct seq_file *m, const ktime_t mstart, ktime_t range) {
    int syscalls_arr_cnt[128];
    uint64_t tmp;
    size_t i;
    ktime_t uptime;

    memset((void*)syscalls_arr_cnt, 0, 128 * sizeof(int));
    uptime = ktime_get_boottime_seconds() - mstart;

    if (uptime < range) {
        range = uptime;
    }

    for (i = 0; i < range; i++) {
        if ((tmp = syscalls_time_array[uptime - i].p1) != 0) {
            walk_bits_and_find_syscalls(m, tmp, syscalls_arr_cnt);
        }

        if ((tmp = syscalls_time_array[uptime - i].p2) != 0) {
            walk_bits_and_find_syscalls(m, tmp, syscalls_arr_cnt + 64);
        }
    }

    show_int_message(m, "Syscall statistics for the last %d seconds.\n\n", range);

    for (i = 0; i < 128; i++) {
        if (syscalls_arr_cnt[i] != 0) {
            show_str_message(m, "%s called ", syscalls_names[i]);
            show_int_message(m, "%d times.\n", syscalls_arr_cnt[i]);
        }
    }
}
