# Linux内核初始化 （第六部分）

## 0 内核剩余部分初始化

在上一篇中，我们进行Linux内核主要部分初始化，现在我们进行最后一步初始化。

## 1 `start_kernel`的最后初始化(`arch_call_rest_init`)

接下来，调用`arch_call_rest_init`函数，该函数很简单，只调用`rest_init`函数。`rest_init`函数同样在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L406)中实现。如下：

```C
noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;

	rcu_scheduler_starting();
	pid = kernel_thread(kernel_init, NULL, CLONE_FS);
	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
	rcu_read_unlock();

	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	system_state = SYSTEM_SCHEDULING;

	complete(&kthreadd_done);

	schedule_preempt_disabled();
	cpu_startup_entry(CPUHP_ONLINE);
}
```

`rcu_scheduler_starting`函数将RCU调度器标记为活跃状态。

`kernel_thread`函数在[kernel/fork.c](https://github.com/torvalds/linux/blob/v5.4/kernel/fork.c#L2444)中实现。创建新的内核线程。它需要三个参数，`fn`为在新的进程里执行的函数；
`arg`为函数的参数，`flags`为标记。`kernel_thread`函数调用`_do_fork`函数，创建新的线程。通过`CLONE_FS`和`CLONE_FILES`标记是父线程和子线程直接共享文件信息和文件系统信息。在`rest_init`函数里我们创建了两个内核线程，`pid = 1`的`kernel_init`线程和`pid = 2`的`kthreadd`线程。

`rcu_read_lock`和`rcu_read_unlock`这两个函数分别标记RCU读的临界区的开始和结束。
`set_cpus_allowed_ptr`函数设置`kernel_init`线程允许运行的CPU。
`find_task_by_pid_ns`函数[kernel/pid.c](https://github.com/torvalds/linux/blob/v5.4/kernel/pid.c#L346)实现，根据pid返回对应的`struct task_struct`。

接下来，调用`complete`函数，传递了一个参数:`kthreadd_done`。`kthreadd_done`的定义如下：

```C
static __initdata DECLARE_COMPLETION(kthreadd_done);

#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
```

展开后，定义了一个`struct completion`的结构，在[include/linux/completion.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/completion.h#L26)中定义。该结构描述了一个代码同步机制，提供了在线程到达某个点或状态时可以提供无竞争的方案。使用`完成(completions)`需要三个步骤：第一步定义`complete`结构，我们通过`COMPLETION_INITIALIZER`实现；第二步调用`wait_for_completion`函数，在调用这个函数后，线程被调用时不在举行执行，而是等待其他没有调用`complete`函数的线程；第三步，调用`complete`函数。

`schedule_preempt_disabled`函数在[kernel/sched/core.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/core.c#L4201)中实现，该函数禁用CPU抢占。

`cpu_startup_entry`函数在[kernel/sched/idle.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/idle.c#L350)中实现，在设置CPU状态后，循环调用`do_idle`函数。如下：

```C
void cpu_startup_entry(enum cpuhp_state state)
{
	arch_cpu_idle_prepare();
	cpuhp_online_idle(state);
	while (1)
		do_idle();
}
```

`cpu_startup_entry`函数在后台调度`init_task`，`cpu_startup_entry`函数的主要功能是消耗空闲的CPU周期。当没有其他程序运行时，`init_task`开始运行。`do_idle`函数检查是否有其他活跃的任务可以切换。

## 2 `init`进程初始化（`kernel_init`）

在`rest_init`函数中，我们创建了两个内核线程，其中一个是`init`线程（调用`kernel_init`函数）。现在我们来看看`kernel_init`函数，该函数同样在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L1105)中实现。

* `kernel_init_freeable`
  
`kernel_init`函数中首先调用的是`kernel_init_freeable`函数。`kernel_init_freeable`函数的执行过程如下：

调用`wait_for_completion(&kthreadd_done)`函数，等待`kthreadd`线程完成所有的设置；
设置`gfp_allowed_mask`为`__GFP_BITS_MASK`，意味着，调度程序已经完全设置，此时系统处于运行状态；
调用`set_mems_allowed`函数，允许所有的CPU和NUMA节点允许访问内存，在[include/linux/cpuset.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/cpuset.h#L152)中实现；
设置`cad`（`Ctrl-Alt-Delete`）的进程id，即：当前任务id；
调用`smp_prepare_cpus`函数准备启动其他的CPU，调用`smp_ops.smp_prepare_cpus`；
调用`workqueue_init`函数初始化工作队列，在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L5866)中实现；
调用`init_mm_internals`函数创建`mm_percpu_wq`工作队列；初始化CPU状态；创建`buddyinfo`, `pagetypeinfo`, `vmstat`, `zoneinfo`的proc信息。在[mm/vmstat.c](https://github.com/torvalds/linux/blob/v5.4/mm/vmstat.c#L1966)中实现；
调用`do_pre_smp_initcalls`函数初始化早期`initcalls`；
调用`lockup_detector_init`函数初始化`lockup detector`（或者`nmi_watchdog`）；在[kernel/watchdog.c](https://github.com/torvalds/linux/blob/v5.4/kernel/watchdog.c#L778)中实现；
调用`smp_init`函数初始化smp，启动所有可用的CPU。在[kernel/smp.c](https://github.com/torvalds/linux/blob/v5.4/kernel/smp.c#L578)中实现；
调用`sched_init_smp`函数初始化smp的调度处理城区。在[kernel/sched/core.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/core.c#L6497)中实现；
调用`page_alloc_init_late`函数进行页分配的后续初始化。在[mm/page_alloc.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_alloc.c#L1934)中实现；
调用`page_ext_init`函数进行扩展页的初始化。在[mm/page_ext.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_ext.c#L366)中实现。

* `do_basic_setup`

接下来，调用`do_basic_setup`函数，在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L1024)中实现。在调用这个函数之前，内核已经完成了初始化，CPU已经已启动并且在运行，内存和进程管理正常工作，接下来，调用`do_basic_setup`函数进行系统功能的初始化。

调用`cpuset_init_smp`函数重新初始化CPU；
`driver_init`函数在[drivers/base/init.c](https://github.com/torvalds/linux/blob/v5.4/drivers/base/init.c#L20)中实现。初始化驱动模块，包括，`devtmpfs`, `devices`, `bus`, `class`, `firmware`, `hypervisor`, `devicetree`等proc目录的建立，`platform`, `cpu`， `memory`, `container`子系统的注册。
`init_irq_proc`函数在[kernel/irq/proc.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/proc.c#L408)中实现。创建`proc/irq`目录；每一个IRQ注册proc信息;
`do_ctors`函数在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L788)中实现。调用所有的构造函数，即，`__ctors_start`和`__ctors_end`之间的函数。
`usermodehelper_enable`函数在[include/linux/umh.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/umh.h#L75)中实现。启用用户模式；
`do_initcalls`函数[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L1009)中实现。调用早期后面的`initcall`，包括：`pure`, `core`, `postcore`, `arch`, `subsys`, `fs`, `device`, `late`等8个层级。

* 打开`console`
  
接下来，打开`rootfs`中`/dev/console`文件，并且复制这个文件描述符两次，即：`0 ~ 2`。如下：

```C
	if (ksys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		pr_err("Warning: unable to open an initial console.\n");

	(void) ksys_dup(0);
	(void) ksys_dup(0);
```

* 挂载`initrd`

首先，检查命令行中`rdinit=`参数，或设置默认的ramdisk路径；检查用户访问`ramdisk`的权限，并调用[init/do_mounts.c](https://github.com/torvalds/linux/blob/v5.4/init/do_mounts.c#L571)中`prepare_namespace`函数挂载`initrd`。如下：

```C
	if (!ramdisk_execute_command)
		ramdisk_execute_command = "/init";

	if (ksys_access((const char __user *)
			ramdisk_execute_command, 0) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}
```

* 释放初始化阶段的内存

在调用`kernel_init_freeable`后，返回`kernel_init`函数，进行后续执行操作。

`async_synchronize_full`函数在[kernel/async.c](https://github.com/torvalds/linux/blob/v5.4/kernel/async.c#L242)中实现，等待所有异步的函数调用都完成。
`ftrace_free_init_mem`函数在[kernel/trace/ftrace.c](https://github.com/torvalds/linux/blob/v5.4/kernel/trace/ftrace.c#L6181)中实现，释放ftrace初始化过程中使用的内存；
`free_initmem`函数在[kernel/trace/ftrace.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/init.c#L862)中实现，释放内核镜像初始化过程使用的内存；
`mark_readonly`函数实现`只读数据段（.rodata）`内存保护；
`pti_finalize`函数在[arch/x86/mm/pti.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/pti.c#L669)实现，实现内核页表和用户页表的映射；

* 运行`init`进程
  
经过上面的设置后，修改系统状态为运行状态（`SYSTEM_RUNNING`）；然后，调用`run_init_process`或`try_to_run_init_process`运行`init`程序。如下：

```C
	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}
		if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		panic("Requested init %s failed (error %d).",
		      execute_command, ret);
	}
	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;
```

`run_init_process`函数填充`argv_init`后，调用`do_execve`函数运行指定的程序和参数。

```C
static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };

static int run_init_process(const char *init_filename)
{
	argv_init[0] = init_filename;
	pr_info("Run %s as init process\n", init_filename);
	return do_execve(getname_kernel(init_filename),
		(const char __user *const __user *)argv_init,
		(const char __user *const __user *)envp_init);
}
```

运行`init`程序的顺序为，`rdinit=`参数 -> `init` -> `init=`参数 -> `/sbin/init` -> `/etc/init` -> `/bin/init` -> `/bin/sh`。

如果，上面的进程均不能正常运行，调用`panic`，如下：

```C
panic("No working init found.  Try passing init= option to kernel. "
	"See Linux Documentation/admin-guide/init.rst for guidance.");
```

## 3 `kthreadd`进程初始化（`kthreadd`）

在`rest_init`函数中，我们创建了两个内核线程，其中一个是`init`线程（调用`kernel_init`函数），在上面已经描述。现在我们来看看`kthreadd`函数，该函数同样在[kernel/kthread.c](https://github.com/torvalds/linux/blob/v5.4/kernel/kthread.c#L568)中实现。 如下：

```C
int kthreadd(void *unused)
{
	struct task_struct *tsk = current;

	set_task_comm(tsk, "kthreadd");
	ignore_signals(tsk);
	set_cpus_allowed_ptr(tsk, cpu_all_mask);
	set_mems_allowed(node_states[N_MEMORY]);

	current->flags |= PF_NOFREEZE;
	cgroup_init_kthreadd();

	for (;;) {
		...
	}

	return 0;
}
```

`set_task_comm`函数设置`task_struct`名称，这里设置为`kthreadd`;
`ignore_signals`函数在[kernel/signal.c](https://github.com/torvalds/linux/blob/v5.4/kernel/signal.c#L518)中实现，设置`task_struct`中信号处理程序为`SIG_IGN`;
`set_cpus_allowed_ptr`和`set_mems_allowed`在上面描述过，设置运行的CPU和运行使用的内存。同样的，设置可以使用所有的CPU和内存；
`current->flags |= PF_NOFREEZE;`设置该进程不被冷冻；

在进行上述设置后，进入该线程的主体函数`for(;;)`。在循环里，判断`kthread_create_list`列表状态，列表为空时，调用`schedule`函数；否则，获取并移除`kthread_create_list`的第一个`struct kthread_create_info`信息，调用`create_kthread`进行处理。

`create_kthread`函数同样在[kernel/kthread.c](https://github.com/torvalds/linux/blob/v5.4/kernel/kthread.c#L270)中实现。创建一个内核线程，该线程调用`kthread`函数。

`kthread`函数同样在[kernel/kthread.c](https://github.com/torvalds/linux/blob/v5.4/kernel/kthread.c#L214)中实现，在进行必要的初始化和检查后，调用`kthread_create_info`中的`threadfn`函数。

## 4 结束语

本文描述了Linux内核`init`进程和`kthread`进程的初始化过程，至此，我们已经完成了Linux内核的所有初始化过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
