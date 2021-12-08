#ifndef __MEMORY_H__
#define __MEMORY_H__

#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/time.h>

#include "log.h"

typedef struct mem_struct {
    long available;
    long free;
    long time_secs;
} mem_info_t;

#define MEMORY_ARRAY_SIZE 8640
extern mem_info_t mem_info_array[MEMORY_ARRAY_SIZE];

extern int mem_info_calls_cnt;

#endif
