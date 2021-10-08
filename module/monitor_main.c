#include <linux/module.h>
#include <linux/proc_fs.h> 
#include <linux/time.h>

#include "hooks.h"
#include "stat.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romanov Alexey");
MODULE_DESCRIPTION("A utility for monitoring the state of the system and kernel load");

static struct proc_dir_entry *proc_root = NULL;
static struct proc_dir_entry *proc_mem_file = NULL, *proc_task_file = NULL, *proc_syscall_file = NULL;

extern ktime_t start_time;
/* default syscall range value is 10 min */
static ktime_t syscalls_range_in_seconds = 600;

static int show_memory(struct seq_file *m, void *v) {
    print_memory_statistics(m);
    return 0;
}

static int proc_memory_open(struct inode *sp_inode, struct file *sp_file) {
    return single_open(sp_file, show_memory, NULL);
}

static int show_tasks(struct seq_file *m, void *v) {
    print_task_statistics(m);
    return 0;
}

static int proc_tasks_open(struct inode *sp_inode, struct file *sp_file) {
    return single_open(sp_file, show_tasks, NULL);
}

static int show_syscalls(struct seq_file *m, void *v) {
    print_syscall_statistics(m, start_time, syscalls_range_in_seconds);
    return 0;
}

static int proc_syscalls_open(struct inode *sp_inode, struct file *sp_file) {
    return single_open(sp_file, show_syscalls, NULL);
}

static int proc_release(struct inode *sp_node, struct file *sp_file) {
    return 0;
}

#define CHAR_TO_INT(ch) (ch - '0')

static ktime_t convert_strf_to_seconds(char buf[]) {
    /* time format: xxhyymzzs. For example: 01h23m45s */
    ktime_t hours, min, secs;

    hours = CHAR_TO_INT(buf[0]) * 10 + CHAR_TO_INT(buf[1]);
    min = CHAR_TO_INT(buf[3]) * 10 + CHAR_TO_INT(buf[4]);
    secs = CHAR_TO_INT(buf[6]) * 10 + CHAR_TO_INT(buf[7]);

    return hours * 60 * 60 + min * 60 + secs;
}

static ssize_t proc_syscall_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos) {
    char syscalls_time_range[10];

    ENTER_LOG();

    if (copy_from_user(&syscalls_time_range, buf, len) != 0)
    {
        EXIT_LOG()
        return -EFAULT;
    }

    syscalls_range_in_seconds = convert_strf_to_seconds(syscalls_time_range);

    EXIT_LOG();
    return len;
}

static const struct proc_ops mem_ops = {
    proc_read: seq_read,
    proc_open: proc_memory_open,
    proc_release: proc_release,
};

static const struct proc_ops tasks_ops = {
    proc_read: seq_read,
    proc_open: proc_tasks_open,
    proc_release: proc_release,
};

static const struct proc_ops syscalls_ops = {
    proc_read: seq_read,
    proc_open: proc_syscalls_open,
    proc_release: proc_release,
    proc_write: proc_syscall_write,
};

static void cleanup(void) {
    ENTER_LOG();

    if (proc_mem_file != NULL) {
        remove_proc_entry("memory", proc_root);
    }

    if (proc_syscall_file != NULL) {
        remove_proc_entry("syscalls", proc_root);
    }

    if (proc_task_file != NULL) {
        remove_proc_entry("tasks", proc_root);
    }

    if (proc_root != NULL) {
        remove_proc_entry(MODULE_NAME, NULL);
    }

    remove_hooks();

    EXIT_LOG();
}

static int proc_init(void) {
    ENTER_LOG();

    if ((proc_root = proc_mkdir(MODULE_NAME, NULL)) == NULL) {
        goto err;
    }

    if ((proc_mem_file = proc_create("memory", 066, proc_root, &mem_ops)) == NULL) {
        goto err;
    }

    if ((proc_task_file = proc_create("tasks", 066, proc_root, &tasks_ops)) == NULL)
    {
        goto err;
    }

    if ((proc_syscall_file = proc_create("syscalls", 066, proc_root, &syscalls_ops)) == NULL)
    {
        goto err;
    }

    EXIT_LOG();
    return 0;

err:
    cleanup();
    EXIT_LOG();
    return -ENOMEM;
}

static int __init md_init(void) {
    int rc;

    ENTER_LOG();

    if ((rc = proc_init())) {
        return rc;
    }

    if ((rc = install_hooks())) {
        cleanup();
        return rc;
    }

    start_time = ktime_get_boottime_seconds();

    printk("%s: module loaded\n", MODULE_NAME);
    EXIT_LOG();

    return 0;
}

static void __exit md_exit(void) { 
    cleanup();

    printk("%s: module unloaded\n", MODULE_NAME); 
}

module_init(md_init);
module_exit(md_exit);
