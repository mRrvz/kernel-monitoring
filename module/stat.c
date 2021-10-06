#include "stat.h"

static inline long convert_to_kb(const long n) {
    return n << (PAGE_SHIFT - 10);
}

void print_memory_statistic(struct seq_file *m) {
    struct sysinfo i;

    ENTER_LOG();

    si_meminfo(&i);

    show_message(m, "Memory total: %ld kB\n", convert_to_kb(i.totalram));
    show_message(m, "Free memory: %ld kB\n", convert_to_kb(i.freeram));
    show_message(m, "Available memory: %ld kB\n", convert_to_kb(si_mem_available()));

    EXIT_LOG();
}

void print_processes_statistic(struct seq_file *m) {
    struct task_struct *task;
    int total = 0, running = 0, interruptible = 0, uninterruptible = 0, stopped = 0, traced = 0;

    ENTER_LOG();

    for_each_process(task) {
        switch (task->__state) {
            case TASK_RUNNING:
                running++;
                break;
            case TASK_INTERRUPTIBLE:
                interruptible++;
                break;
            case TASK_UNINTERRUPTIBLE:
                uninterruptible++;
                break;
            case __TASK_STOPPED:
                stopped++;
                break;
            case __TASK_TRACED:
                traced++;
                break;
            case TASK_IDLE:
            /* #define TASK_IDLE   (TASK_UNINTERRUPTIBLE | TASK_NOLOAD)
               TASK_NOLOAD - mark s uninteruptible process that doesn’t contribute to
               load average (hence no-load). */
                uninterruptible++;
                break;
            default:
                printk(KERN_INFO "%d %s %d\n", task->__state, task->comm, task->pid);
        }

        total++;
    }

    show_message(m, "Total processes: %d\n", total);
    show_message(m, "Interruptible: %d\n", interruptible);
    show_message(m, "Uninterruptible: %d\n", uninterruptible);
    show_message(m, "Stopped: %d\n", stopped);
    show_message(m, "Traced: %d\n", traced);

    EXIT_LOG();
}

syscalls_info_t syscalls_time_array[TIME_ARRAY_SIZE];

static inline void walk_bits_and_find_syscalls(struct seq_file *m, uint64_t num) {
    int i;

    for (i = 0; i < 64; i++) {
        if (num & (1UL << i)) {
            show_message(m, "==== %d\n", i);
            show_message(m, "%lld ======\n", num);
        }
    }
}

void print_syscall_statistic(struct seq_file *m) {
    size_t i;
    uint64_t tmp;

    for (i = 0; i < TIME_ARRAY_SIZE; i++) {
        tmp = syscalls_time_array[i].p1;
        if (tmp != 0) {
            walk_bits_and_find_syscalls(m, tmp);
        }

        tmp = syscalls_time_array[i].p2;
        if (tmp != 0) {
            walk_bits_and_find_syscalls(m, tmp);
        }
    }
}
