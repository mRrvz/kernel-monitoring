#include "tasks.h"

void print_processes_statistic(struct seq_file *m) {
    struct task_struct *task;
    int total = 0, running = 0, interruptible = 0, uninterruptible = 0, stopped = 0, traced = 0;

    //ENTER_LOG();

    for_each_process(task) {
        switch (task->state) {
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
               TASK_NOLOAD - marks uninteruptible process that doesn’t contribute to
               load average (hence no-load). */
                uninterruptible++;
                break;
            default:
                printk(KERN_INFO "%ld %s %d\n", task->state, task->comm, task->pid);
        }

        total++;
    }

    print_to_user(m, "Total processes: %d\n", total);
    print_to_user(m, "Interruptible: %d\n", interruptible);
    print_to_user(m, "Uninterruptible: %d\n", uninterruptible);
    print_to_user(m, "Stopped: %d\n", stopped);
    print_to_user(m, "Traced: %d\n", traced);

    //EXIT_LOG();
}
