#include <linux/module.h>
#include <linux/mm.h>
#include <linux/proc_fs.h> 
#include <linux/seq_file.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romanov Alexey");
MODULE_DESCRIPTION("A utility for monitoring the state of the system and kernel load");

#define MODULE_NAME "monitor"

#define ENTER_LOG() do { printk(KERN_INFO "%s: function entry %s | line: %d\n", MODULE_NAME, __func__, __LINE__); } while(0); 
#define EXIT_LOG() do { printk(KERN_INFO "%s: exit function %s | line: %d\n", MODULE_NAME, __func__, __LINE__); } while(0);

static struct proc_dir_entry *proc_file = NULL;

static inline void mem_print(struct seq_file *m, const char *const f, long num) {
    char tmp[256];
    int len;

    len = snprintf(tmp, 256, f, num << (PAGE_SHIFT - 10));
    seq_write(m, tmp, len);
}

static int monitor_read(struct seq_file *m, void *v) {
    struct sysinfo i;
    long available;

    ENTER_LOG();

    si_meminfo(&i);
    available = si_mem_available();

    mem_print(m, "Memory total: %ld kB\n", i.totalram);
    mem_print(m, "Free memory: %ld kB\n", i.freeram);
    mem_print(m, "Available memory: %ld kB\n", available);

    EXIT_LOG();

    return 0;
}

static void cleanup(void) {
    ENTER_LOG();

    if (proc_file != NULL) {
        remove_proc_entry(MODULE_NAME, NULL);
    }

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
