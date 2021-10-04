#include <linux/module.h>
#include <linux/mm.h>
#include <linux/proc_fs.h> 
#include <linux/seq_file.h>

#include "hooks.h"
#include "memory.h"
#include "tasks.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romanov Alexey");
MODULE_DESCRIPTION("A utility for monitoring the state of the system and kernel load");

#define MODULE_NAME "monitor"

#define ENTER_LOG() do { printk(KERN_INFO "%s: function entry %s | line: %d\n", MODULE_NAME, __func__, __LINE__); } while(0); 
#define EXIT_LOG() do { printk(KERN_INFO "%s: exit function %s | line: %d\n", MODULE_NAME, __func__, __LINE__); } while(0);

static struct proc_dir_entry *proc_file = NULL;

static inline void print_to_user(struct seq_file *m, const char *const f, const long num) {
    char tmp[256];
    int len;

    len = snprintf(tmp, 256, f, num);
    seq_write(m, tmp, len);
}

static struct ftrace_hook hooked_functions[] = {
        HOOK("sys_clone",   hook_sys_clone,   &real_sys_clone),
        //HOOK("sys_execve",  fh_sys_execve,  &real_sys_execve),
};

static int monitor_read(struct seq_file *m, void *v) {

    ENTER_LOG();

    print_memory_statistic(m);
    print_processes_statistic(m);

    EXIT_LOG();

    return 0;
}

static void cleanup(void) {
    ENTER_LOG();

    if (proc_file != NULL) {
        remove_proc_entry(MODULE_NAME, NULL);
    }

    remove_hooks(hooked_functions, ARRAY_SIZE(hooked_functions));

    EXIT_LOG();
}

static int proc_init(void) {
    ENTER_LOG();

    if ((proc_file = proc_create_single(MODULE_NAME, 066, NULL, monitor_read)) == NULL)
    {
        cleanup();
        EXIT_LOG();

        return -ENOMEM;
    }

    printk("%s: module loaded\n", MODULE_NAME); 
    EXIT_LOG();

    return 0;
}

static int __init md_init(void) {
    int rc;

    ENTER_LOG();

    if ((rc = proc_init())) {
        return rc;
    }

    EXIT_LOG();

    return 0;
}

static void __exit md_exit(void) { 
    cleanup();

    printk("%s: module unloaded\n", MODULE_NAME); 
}

module_init(md_init);
module_exit(md_exit);
