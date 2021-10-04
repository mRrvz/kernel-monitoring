#include "hooks.h"

static asmlinkage long hook_sys_clone(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	long ret;

	//pr_info("clone() before\n");

	ret = real_sys_clone(clone_flags, newsp, parent_tidptr,
		child_tidptr, tls);

	pr_info("clone(): %ld\n", ret);

	return ret;
}

static void remove_hook(struct ftrace_hook *hook) {
    int rc;

	if ((rc = unregister_ftrace_function(&hook->ops)))
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	if ((rc = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0)));
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

void remove_hooks(struct ftrace_hook hooks[], const size_t cnt) {
    for (size_t i = 0; i < cnt; i++) {
        remove_hook(hooks[i]);
    }
}
