#ifndef __STAT_H__
#define __STAT_H__

#include <linux/mm.h>
#include <linux/seq_file.h>
#include "hooks.h"

void print_processes_statistic(struct seq_file *m);
void print_memory_statistic(struct seq_file *m);
void print_syscall_statistic(struct seq_file *m);

#endif
