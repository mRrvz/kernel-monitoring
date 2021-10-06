#include "log.h"

void show_message(struct seq_file *m, const char *const f, const long num)
{
    char tmp[256];
    int len;

    len = snprintf(tmp, 256, f, num);
    seq_write(m, tmp, len);
}
