#ifndef __STAT_H__
#define __STAT_H__

#include <linux/mm.h>
#include <linux/seq_file.h>

#include "hooks.h"
#include "memory.h"

void print_task_statistics(struct seq_file *m);
void print_memory_statistics(struct seq_file *m);
void print_syscall_statistics(struct seq_file *m, const ktime_t mstart, ktime_t range);

#endif
