#include "log.h"

void show_int_message(struct seq_file *m, const char *const f, const long num) {
    char tmp[256];
    int len;

    len = snprintf(tmp, 256, f, num);
    seq_write(m, tmp, len);
}

void show_int3_message(struct seq_file *m, const char *const f, const long n1, const long n2, const long n3) {
    char tmp[256];
    int len;

    len = snprintf(tmp, 256, f, n1, n2, n3);
    seq_write(m, tmp, len);
}

void show_str_message(struct seq_file *m, const char *const f, const char *const s) {
    char tmp[256];
    int len;

    len = snprintf(tmp, 256, f, s);
    seq_write(m, tmp, len);
}
