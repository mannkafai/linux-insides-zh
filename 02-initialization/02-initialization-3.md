# Linux内核初始化 （第三部分）

## 0 内核入口点

在上一篇中，Linux内核已经在`arch/x86/kernel/head64.c`中调用`start_kernel`，已经进入内核入口点。在`start_kernel`函数是与体系架构无关的通用处理入口函数，尽管我们在此初始化过程中需要无数次返回`arch`文件夹。我们接下来分析其处理过程。

## 1 内核入口点函数（`start_kernel`）

`start_kernel`函数在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L575)中定义。如下：

```C
asmlinkage __visible void __init start_kernel(void)
{
	char *command_line;
	char *after_dashes;

    ...
}
```

### 1.1 关于`__attribute__`

可以看到`start_kernel`函数使用了`__visible`和`__init`特性。`__visible`特性告诉编译器其他函数在使用该函数或变量，为了防止标记这个函数或变量是`unusable`。在内核初始化阶段所有的函数都需要使用`__init`特性，其定义如下：

```C
#define __init		__section(.init.text) __cold  __latent_entropy __noinitretpoline
```

在初始化完成后，内核通过调用`free_initmem`来释放这些段(section)。可以看到`__init`通过其他几个属性定义的，`__cold`属性用来标记该函数很少使用，编译器必须优化此函数的大小。

## 2 平台初始化前的设置

### 2.1 设置任务栈底边界（`set_task_stack_end_magic`）

这是进入`start_kernel`后第一个调用的函数。在[kernel/fork.c](https://github.com/torvalds/linux/blob/v5.4/kernel/fork.c#L848)中实现。该函数获取`init_task`的栈尾并将其设置为`STACK_END_MAGIC(0x57AC6E9D)`。如下：

```C
void set_task_stack_end_magic(struct task_struct *tsk)
{
	unsigned long *stackend;
	stackend = end_of_stack(tsk);
	*stackend = STACK_END_MAGIC;	/* for overflow detection */
}
```

`init_task`表示初始化进程(或任务)的数据结构，在[init/init_task.c](https://github.com/torvalds/linux/blob/v5.4/init/init_task.c#L56)中定义。如下：

```C
struct task_struct init_task
#ifdef CONFIG_ARCH_TASK_STRUCT_ON_STACK
	__init_task_data
#endif
= {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	.thread_info	= INIT_THREAD_INFO(init_task),
	.stack_refcount	= REFCOUNT_INIT(1),
#endif
	.state		= 0,
	.stack		= init_stack,
	.usage		= REFCOUNT_INIT(2),
	.flags		= PF_KTHREAD,

	...

#ifdef CONFIG_SECURITY
	.security	= NULL,
#endif
};
EXPORT_SYMBOL(init_task);
```

`init_task`是一个`struct task_struct`结构体，它存储了有关进程的所有信息，在[include/linux/sched.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/sched.h#L624)中定义。`struct task_struct`的结构体比较庞大，包含了100多个字段，我们会经常使用到它，它是Linux内核中进程(Process)的基本结构。`init_task`设置和初始化了第一个进程的值，设置如下：

* 初始化`state`为0（或者，runnable），即：一个等待CPU运行的进程；
* 初始化`flags`为`PF_KTHREAD`，即：内核线程；
* 初始化栈信息`stack`为`init_stack`;
* 可运行的任务列表`tasks`;
* 内存地址空间`active_mm`;
* 初始化`thread_info`;
* ...
  
`init_stack`在[include/asm-generic/vmlinux.lds.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/vmlinux.lds.h#L320)定义，如下：

```C
#define INIT_TASK_DATA(align)						\
	. = ALIGN(align);						\
	__start_init_task = .;						\
	init_thread_union = .;						\
	init_stack = .;							\
	KEEP(*(.data..init_task))					\
	KEEP(*(.data..init_thread_info))				\
	. = __start_init_task + THREAD_SIZE;				\
	__end_init_task = .;
```

`thread_info`结构体在[arch/x86/include/asm/thread_info.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/thread_info.h#L56)中定义，只有`flags`和`status`两个字段，如下：

```C
struct thread_info {
	unsigned long		flags;		/* low level flags */
	u32			status;		/* thread synchronous flags */
};
```

### 2.2 激活CPU前的早期设置

* SMP设置处理器ID

`smp_setup_processor_id`函数在`x86_64`平台下是个空函数，该函数在一部分平台（如：arm64等）下实现。

* 调试信息早期初始化

`debug_objects_early_init`函数根据`CONFIG_DEBUG_OBJECTS`内核配置选项实现不同。在开启的情况下，在[lib/debugobjects.c](https://github.com/torvalds/linux/blob/v5.4/lib/debugobjects.c#L1277)中实现，填充`obj_hash`和`obj_static_pool`调试信息。

* cgroup早期初始化
  
`cgroup_init_early`函数在[kernel/cgroup/cgroup.c](https://github.com/torvalds/linux/blob/v5.4/kernel/cgroup/cgroup.c#L5677)中实现，进行cgroup相关初始化。

### 2.3 禁用本地中断（`local_irq_disable`）

接下来，我们需要禁用本地[IRQ](https://en.wikipedia.org/wiki/Interrupt_request_%28PC_architecture%29)。通过调用[include/linux/irqflags.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irqflags.h#L140)中的`local_irq_disable`函数来实现。`local_irq_disable`最终会调用`arch_local_irq_disable`。

`arch_local_irq_disable`根据平台的不同实现不同。在`x86_64`下，调用`native_irq_disable`,最终调用`cli`指令。

### 2.4 激活第一个CPU（`boot_cpu_init`）

`boot_cpu_init`在[kernel/cpu.c](https://github.com/torvalds/linux/blob/v5.4/kernel/cpu.c#L2350)中实现。

* 获取当前处理器ID

首先，我们需要获取当前CPU的ID，通过`smp_processor_id`获取。`smp_processor_id`在[include/linux/smp.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/smp.h#L211)展开为`__smp_processor_id`。目前是0，在`CONFIG_SMP`的情况下，在[arch/x86/include/asm/smp.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/smp.h#L167)展开为`this_cpu_read(cpu_number)`。

`this_cpu_read`同其他函数一样（如：`this_cpu_write`, `this_cpu_and`, `this_cpu_or`等）定义在[include/linux/percpu-defs.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/percpu-defs.h#L444)中，提供对`percpu`变量的访问。以`this_cpu_read`为例，

```C
#define this_cpu_read(pcp)		__pcpu_size_call_return(this_cpu_read_, pcp)

#define __pcpu_size_call_return(stem, variable)				\
({									\
	typeof(variable) pscr_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr_ret__ = stem##1(variable); break;			\
	case 2: pscr_ret__ = stem##2(variable); break;			\
	case 4: pscr_ret__ = stem##4(variable); break;			\
	case 8: pscr_ret__ = stem##8(variable); break;			\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pscr_ret__;							\
})
```

`__pcpu_size_call_return`的实现很简单，但是比较奇怪。`pscr_ret__`变量定义为`int`类型，是因为`variable`是`cpu_number`，它的定义如下：

```C
DECLARE_PER_CPU_READ_MOSTLY(int, cpu_number);
```

* 验证CPU指针变量

接下来，调用`__verify_pcpu_ptr`来验证`cpu_number`的地址是否一个有效的`precpu`变量指针。然后，根据`variable`的占用的类型大小来获取`pscr_ret__`。我们的`cpu_number`变量是`int`类型（即4个字节），因此，我们执行`pscr_ret__ = this_cpu_read_4(cpu_number)`。

`this_cpu_read_4`是个宏定义，最终调用汇编语句，展开如下：

```C
#define this_cpu_read_4(pcp)		percpu_from_op(volatile, "mov", pcp)

#define percpu_from_op(qual, op, var)			\
({							\
	typeof(var) pfo_ret__;				\
	switch (sizeof(var)) {				\
	case 1:						\
		...
		break;					\
	case 2:						\
		...	
		break;					\
	case 4:						\
		asm qual (op "l "__percpu_arg(1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "m" (var));			\
		break;					\
	case 8:						\
		...
		break;					\
	default: __bad_percpu_size();			\
	}						\
	pfo_ret__;					\
})
```

由于，我们没有设置`percpu`区域，目前只有一个CPU，`smp_processor_id`的返回结果为`0`。

* 设置CPU状态

在得到当前处理器id后，`boot_cpu_init`设置CPU的在线、激活状态，包括：`online`,`active`,`present`,`possible`，如下：

```C
set_cpu_online(cpu, true);
set_cpu_active(cpu, true);
set_cpu_present(cpu, true);
set_cpu_possible(cpu, true);
```

上述我们使用的这些CPU配置称为CPU掩码（cpumask）。`cpu_possible_mask`表示可填充的CPU；`cpu_present_mask`表示已填充的CPU；`cpu_online_mask`表示可用于调度程序的CPU；`cpu_active_mask`表示可用于迁移的CPU。这些设置功能相似，通过第二个参数来调用`cpumask_set_cpu`或`cpumask_clear_cpu`来改变对应`cpumask`的状态。`cpumask`的定义如下：

```C
typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]
```

可以看到`cpumask_t`是一个`unsigned long`类型的数组，使用`bitmap`来表示当前系统中CPU，每个CPU使用`1bit`。

`cpumask_set_cpu`或`cpumask_clear_cpu`最终通过`set_bit`或`clear_bit`来改变对应的状态。如下：

```C
static inline void
set_cpu_active(unsigned int cpu, bool active)
{
	if (active)
		cpumask_set_cpu(cpu, &__cpu_active_mask);
	else
		cpumask_clear_cpu(cpu, &__cpu_active_mask);
}

static inline void cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
	set_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

static inline void cpumask_clear_cpu(int cpu, struct cpumask *dstp)
{
	clear_bit(cpumask_check(cpu), cpumask_bits(dstp));
}
```

### 2.5 打印Linux编译信息（Linux banner）

调用`pr_notice`函数（printk的扩展），打印Linux的banner，包括内核版本以及编译环境信息。

```C
#define pr_notice(fmt, ...) \
	pr_printk_hash(KERN_NOTICE, fmt, ##__VA_ARGS__)

#define pr_printk_hash(level, format, ...) \
	printk(level pr_fmt(format), ##__VA_ARGS__)
```

`linux_banner`在[init/version.c](https://github.com/torvalds/linux/blob/v5.4/init/version.c#L46)定义，如下：

```C
const char linux_banner[] =
	"Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@"
	LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n";
```

### 2.6 其他早期初始化

* 页地址初始化
  
`page_address_init`函数在内存不能直接映射时（如：highmem）执行，在当前情况下为空函数。

* 早期安全初始化

`early_security_init`在[security/security.c](https://github.com/torvalds/linux/blob/v5.4/security/security.c#L329)实现，进行安全早期初始化。

### 2.7 平台相关初始化（`setup_arch`）

接下来，调用`setup_arch`函数进行平台相关设置。

## 3 结束语

本文描述了Linux内核平台入口函数，主要进行`init`进程的设置和CPU的设置。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
