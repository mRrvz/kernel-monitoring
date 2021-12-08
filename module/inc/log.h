#ifndef __LOG_H__
#define __LOG_H__

#include <linux/seq_file.h>
#include <linux/module.h>

#define MODULE_NAME "monitor"

void show_int_message(struct seq_file *m, const char *const f, const long num);
void show_str_message(struct seq_file *m, const char *const f, const char *const s);
void show_int3_message(struct seq_file *m, const char *const f, const long, const long, const long);

#define ENTER_LOG() do { printk(KERN_INFO "%s: function entry %s | line: %d\n", MODULE_NAME, __func__, __LINE__); } while(0);
#define EXIT_LOG() do { printk(KERN_INFO "%s: exit function %s | line: %d\n", MODULE_NAME, __func__, __LINE__); } while(0);

#endif 
