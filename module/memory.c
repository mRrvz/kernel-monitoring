#include "memory.h"

static inline long convert_to_kb(const long n) {
    return n << (PAGE_SHIFT - 10);
}

void print_memory_statistic(struct seq_file *m) {
    //ENTER_LOG();

    struct sysinfo i;

    si_meminfo(&i);

    print_to_user(m, "Memory total: %ld kB\n", convert_to_kb(i->totalram));
    print_to_user(m, "Free memory: %ld kB\n", convert_to_kb(i->freeram));
    print_to_user(m, "Available memory: %ld kB\n", convert_to_kb(si_mem_available()));

    //EXIT_LOG();
}
