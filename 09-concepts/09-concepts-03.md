# initcall 机制

## 0 initcall机制的介绍

这部分将涉及 Linux 内核中有趣且重要的概念，称之为 `initcall`。在 Linux 内核中，我们可以看到类似这样的定义：

```C
early_param("debug", debug_kernel);
```

或者

```C
arch_initcall(init_pit_clocksource);
```

在我们分析这个机制在内核中是如何实现的之前，我们首先了解这个机制是什么。像这样的定义表示一个[回调函数](https://en.wikipedia.org/wiki/Callback_(computer_programming))，它们会在 Linux 内核启动中或启动后调用。`initcall` 机制的要点是确定内置模块和子系统初始化的正确顺序。

举个例子，我们来看看下面的函数：

```C
static int __init nmi_warning_debugfs(void)
{
    debugfs_create_u64("nmi_longest_ns", 0644,
                       arch_debugfs_dir, &nmi_longest_ns);
    return 0;
}
fs_initcall(nmi_warning_debugfs);
```

这个函数出自源码文件[arch/x86/kernel/nmi.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/nmi.c#L99)，这个函数在 `arch_debugfs_dir` 目录中创建 `nmi_longest_ns` [debugfs](https://en.wikipedia.org/wiki/Debugfs) 文件。实际上，只有在 `arch_debugfs_dir` 目录创建后，才会创建这个 `debugfs` 文件。而 `arch_debugfs_dir` 目录在[arch/x86/kernel/kdebugfs.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/kdebugfs.c#L151)文件中的 `arch_kdebugfs_init` 函数中创建。如下：

```C
static int __init arch_kdebugfs_init(void)
{
	int error = 0;
	arch_debugfs_dir = debugfs_create_dir("x86", NULL);
#ifdef CONFIG_DEBUG_BOOT_PARAMS
	error = boot_params_kdebugfs_init();
#endif
	return error;
}
arch_initcall(arch_kdebugfs_init);
```

Linux 内核在调用 `fs` 相关的 `initcalls` 之前调用所有特定架构的 `initcalls`。因此，只有在 `arch_kdebugfs_dir` 目录创建以后才会创建 `nmi_longest_ns` 文件。

Linux内核提供了旧个级别的主 `initcalls` ：

* `early`;
* `pure`;
* `core`;
* `postcore`;
* `arch`;
* `susys`;
* `fs`;
* `device`;
* `late`.

它们的所有名称是由数组 `initcall_level_names` 来描述的，该数组在源码文件 [init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L982)中定义，如下：

```C
static const char *initcall_level_names[] __initdata = {
	"pure",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};
```

所有用这些标识符标记为 `initcall` 的函数将会以相同的顺序被调用，或者说，`early initcalls` 会首先被调用，其次是 `pure initcalls`，以此类推。现在，我们对 `initcall` 机制有所了解，接下来，我们开始深入Linux 内核源码，来看看这个机制是如何实现的。

## 1 initcall机制的实现

### 1.1 initcall的定义

Linux内核在[include/linux/init.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/init.h#L207)文件中提供了一组宏来标记给定的函数为 `initcall`。所有这些宏都相当简单，如下：

```C
#define early_initcall(fn)		__define_initcall(fn, early)

#define pure_initcall(fn)		__define_initcall(fn, 0)

#define core_initcall(fn)		__define_initcall(fn, 1)
#define postcore_initcall(fn)		__define_initcall(fn, 2)
#define arch_initcall(fn)		__define_initcall(fn, 3)
#define subsys_initcall(fn)		__define_initcall(fn, 4)
#define fs_initcall(fn)			__define_initcall(fn, 5)
#define rootfs_initcall(fn)		__define_initcall(fn, rootfs)
#define device_initcall(fn)		__define_initcall(fn, 6)
#define late_initcall(fn)		__define_initcall(fn, 7)
```

我们可以看到，这些宏只是扩展到同一个文件中的 `__define_initcall` 宏。`__define_initcall` 宏有两个参数：`fn` -- 在调用某个级别 `initcalls` 时调用的回调函数；`id` -- `initcall` 的标识符。

`__define_initcall` 宏扩展`___define_initcall`宏，传入了第三个参数`.initcall##id`。之间的[##](https://gcc.gnu.org/onlinedocs/cpp/Concatenation.html)表示连接了两个符号。如下：

```C
#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)

#define ___define_initcall(fn, id, __sec) \
	static initcall_t __initcall_##fn##id __used \
		__attribute__((__section__(#__sec ".init"))) = fn;
```

在了解 `__define_initcall` 宏之前，首先让我们来看下 `initcall_t` 类型。这个类型同样在[include/linux/init.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/init.h#L116)中定义，它表示一个返回[整形](https://en.wikipedia.org/wiki/Integer)指针的函数指针，这将是 `initcall` 的结果：

```C
typedef int (*initcall_t)(void);
```

现在让我们回到 `___define_initcall` 宏，它定义了名称为 `__initcall_<function-name>_<id>` 的`initcall_t`函数，该函数具有`__used` 属性，并位于 `.initcall<id>.init` [ELF段](http://www.skyfree.org/linux/references/ELF_Format.pdf)中。如果我们查看表示内核链接脚本数据的 [include/asm-generic/vmlinux.lds.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/vmlinux.lds.h) 头文件，我们会看到所有的 `initcalls` 部分都将放在 `.data` 段。如下：

```C
#define INIT_CALLS_LEVEL(level)						\
		__initcall##level##_start = .;				\
		KEEP(*(.initcall##level##.init))			\
		KEEP(*(.initcall##level##s.init))			\

#define INIT_CALLS							\
		__initcall_start = .;					\
		KEEP(*(.initcallearly.init))				\
		INIT_CALLS_LEVEL(0)					\
		INIT_CALLS_LEVEL(1)					\
		INIT_CALLS_LEVEL(2)					\
		INIT_CALLS_LEVEL(3)					\
		INIT_CALLS_LEVEL(4)					\
		INIT_CALLS_LEVEL(5)					\
		INIT_CALLS_LEVEL(rootfs)				\
		INIT_CALLS_LEVEL(6)					\
		INIT_CALLS_LEVEL(7)					\
		__initcall_end = .;


#define INIT_DATA_SECTION(initsetup_align)				\
	.init.data : AT(ADDR(.init.data) - LOAD_OFFSET) {		\
		INIT_DATA						\
		INIT_SETUP(initsetup_align)				\
		INIT_CALLS						\
		CON_INITCALL						\
		INIT_RAM_FS						\
	}
```

第二个属性 - `__used`，定义在 [include/linux/compiler_attributes.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/compiler_attributes.h#L265) 头文件中，它扩展了以下 `gcc` 定义，该属性防止 `定义了变量但未使用`的告警，如下：

```C
#define __used   __attribute__((__used__))
```

这就是关于 `__define_initcall` 宏的全部内容。所有的 `*_initcall` 宏将会在Linux内核编译时扩展，所有的 `initcalls` 会放置在它们的段内，并可以通过 `.data` 段来获取。Linux 内核在初始化过程中就知道在哪儿去找到特定的 `initcall` 。

### 1.2 initcall的调用过程

#### 1.2.1 initcall级别调用

既然 Linux 内核可以调用 `initcalls`，我们就来看下 Linux 内核是如何做的。在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L1034)文件的 `do_pre_smp_initcalls` 函数和 `do_basic_setup` 函数中进行相关调用。

`do_pre_smp_initcalls` 函数在SMP初始化前调用，进行`early`级别的initcall调用，如下：

```C
static void __init do_pre_smp_initcalls(void)
{
	initcall_entry_t *fn;

	trace_initcall_level("early");
	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(initcall_from_entry(fn));
}
```

`do_basic_setup` 函数在SMP初始化后进行调用，进行Linux系统功能的初始化，比如驱动初始化等。在最后调用`do_initcalls`函数，`do_initcalls` 函数只是遍历 `initcall` 级别数组，并调用每个级别的 `do_initcall_level` 函数。如下：

```C
static void __init do_basic_setup(void)
{
	...
	...
	...
	do_initcalls();
}
...
static void __init do_initcalls(void)
{
	int level;

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++)
		do_initcall_level(level);
}
```

`initcall_levels` 数组在同一个源码[文件](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L969)中定义，包含了定义在 `__define_initcall` 宏中的那些段的指针：

```C
typedef initcall_t initcall_entry_t;

static initcall_entry_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};
```

如果你有兴趣，你可以在 Linux 内核编译后生成的链接器脚本 `arch/x86/kernel/vmlinux.lds` 中找到这些段：

```bash
.init.data : AT(ADDR(.init.data) - 0xffffffff80000000) {
    ...
    ...
    ...
    ...
    __initcall_start = .;
    KEEP(*(.initcallearly.init))
    __initcall0_start = .;
    KEEP(*(.initcall0.init))
    KEEP(*(.initcall0s.init))
    __initcall1_start = .;
    ...
    ...
}
```

正如我们刚看到的，`do_initcall_level` 函数有一个参数 - `initcall` 的级别，做了以下两件事：首先这个函数拷贝了 `initcall_command_line`，这是通常内核包含了各个模块参数的[命令行](https://github.com/torvalds/linux/blob/v5.4/Documentation/admin-guide/kernel-parameters.txt)的副本，并用 [kernel/params.c](https://github.com/torvalds/linux/blob/v5.4/kernel/params.c#L161)源码文件的 `parse_args` 函数解析它，然后调用各个级别的 `do_one_initcall` 函数。如下：

```C
static void __init do_initcall_level(int level)
{
	initcall_entry_t *fn;

	strcpy(initcall_command_line, saved_command_line);
	parse_args(initcall_level_names[level],
		   initcall_command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, &repair_env_string);

	trace_initcall_level(initcall_level_names[level]);
	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(initcall_from_entry(fn));
}
```

#### 1.2.2 initcall执行过程

`do_one_initcall` 为我们做了主要的工作。我们可以看到，这个函数有一个参数表示 `initcall` 回调函数，并调用给定的回调函数。如下：

```C
int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	char msgbuf[64];
	int ret;

	if (initcall_blacklisted(fn))
		return -EPERM;

	...
	...
}
```

* 获取抢占计数
  
首先我们获取 [preemption](https://en.wikipedia.org/wiki/Preemption_(computing)) 计数，以便我们稍后进行检查。

* 检查是否在黑名单中

在这之后，调用 `initcall_blacklisted` 函数检查是否在黑名单中。`initcall_blacklisted` 函数依赖`CONFIG_KALLSYMS` 内核配置选项，在关闭的情况下返回`false`。否则，遍历`blacklisted_initcalls` 链表，检查是否包含在黑名单中：

```C
	list_for_each_entry(entry, &blacklisted_initcalls, next) {
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			return true;
		}
	}
```

黑名单的 `initcalls` 保存在 `blacklisted_initcalls` 链表中，这个链表是在早期 Linux 内核初始化时由 Linux 内核命令行来填充的。如下：

```C
__setup("initcall_blacklist=", initcall_blacklist);
```

* `initcall` 的调用
  
处理完进入黑名单的 `initcalls`，接下来的代码直接调用 `initcall`：

```C
	do_trace_initcall_start(fn);
	ret = fn();
	do_trace_initcall_finish(fn, ret);
```

`do_trace_initcall_start` 函数和`do_trace_initcall_finish` 函数进行 `initcall` 调用前后的追踪。如下：

```C
static inline void do_trace_initcall_start(initcall_t fn)
{
	if (!initcall_debug)
		return;
	trace_initcall_start_cb(&initcall_calltime, fn);
}
static inline void do_trace_initcall_finish(initcall_t fn, int ret)
{
	if (!initcall_debug)
		return;
	trace_initcall_finish_cb(&initcall_calltime, fn, ret);
}
```

`initcall`调用是否进行追踪取决于 `initcall_debug` 变量的值，`initcall_debug` 变量同样在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L512)中定义：

```C
bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);
```

可以通过 `initcall_debug` 参数从内核命令行中设置这个变量的值。从Linux内核命令行[文档](https://github.com/torvalds/linux/blob/v5.4/Documentation/admin-guide/kernel-parameters.txt#L1671)可以看到：

```text
	initcall_debug	[KNL] Trace initcalls as they are executed.  Useful
			for working out where the kernel is dying during
			startup.
```

在开启追踪的情况下，打印了一些和 `initcall` 相关的信息（比如当前任务的 [pid](https://en.wikipedia.org/wiki/Process_identifier)、`initcall` 的持续时间等），如下：

```C
static __init_or_module void
trace_initcall_start_cb(void *data, initcall_t fn)
{
	unsigned long *calltime = (unsigned long *)data;

	printk(KERN_DEBUG "calling  %pS @ %i\n", fn, task_pid_nr(current));
	*calltime = local_clock();
}

static __init_or_module void
trace_initcall_finish_cb(void *data, initcall_t fn, int ret)
{
	...
	rettime = local_clock();
	delta = rettime - *calltime;
	duration = delta >> 10;
	printk(KERN_DEBUG "initcall %pS returned %d after %lld usecs\n",
		 fn, ret, duration);
}
```

* 执行后的检查
  
我们可以看到在 `do_one_initcall` 函数末尾做了两次检查。第一次检查抢占计数，如果这个值和之前的可抢占计数不相等，输出 `preemption imbalance` 信息，并设置正确的可抢占计数：

```C
	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
```

最后检查本地 [IRQs](https://en.wikipedia.org/wiki/Interrupt_request_%28PC_architecture%29) 的状态，如果它们被禁用了，输出 `disabled interrupts` 信息，并启用本地`IRQs`，防止出现 `IRQs` 被 `initcall` 禁用后不再使能的情况：

```C
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
```

这就是`initcall`调用的整个过程。通过这种方式，Linux 内核以正确的顺序完成了很多子系统的初始化。

### 1.3 initcall的其他内容

现在我们知道 Linux 内核中 `initcall` 机制是怎么回事了。我们仍遗留了一些重要的概念，接下来，让我们来简单看下这些概念。

* `rootfs initcalls`

首先，我们错过了一个级别的 `initcalls`，就是 `rootfs initcalls`。和我们在本部分看到的很多宏类似，你可以在 [include/linux/init.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/init.h#L228) 头文件中找到 `rootfs_initcall` 的定义：

```C
#define rootfs_initcall(fn)		__define_initcall(fn, rootfs)
```

从这个宏的名字我们可以理解到，它的主要目的是保存和 [rootfs](https://en.wikipedia.org/wiki/Initramfs) 相关的回调。除此这个目的之外，在文件系统初始化完成后，设备相关内容初始化前，我们进行一些组件的初始化。例如，在[init/initramfs.c](https://github.com/torvalds/linux/blob/v5.4/init/initramfs.c#L680)文件中 `populate_rootfs` 函数里的解压  [initramfs](https://en.wikipedia.org/wiki/Initramfs)：

```C
rootfs_initcall(populate_rootfs);
```

在这里，我们可以看到熟悉的输出：

```bash
[    0.199960] Unpacking initramfs...
```

除了 `rootfs_initcall` 级别，还有其他辅助的 `initcall` 级别，如： `console_initcall`。

* `*_initcall_sync`

此外，我们还遗留了 `*_initcall_sync` 级别的集合。在这部分我们看到的几乎每个 `*_initcall` 宏，都有 `_sync` 前缀的宏。这些级别的`initcall` 的主要目的是等待对应级别的所有模块相关的初始化完成后调用。如下：

```C
#define core_initcall_sync(fn)		__define_initcall(fn, 1s)
#define postcore_initcall_sync(fn)	__define_initcall(fn, 2s)
#define arch_initcall_sync(fn)		__define_initcall(fn, 3s)
#define subsys_initcall_sync(fn)	__define_initcall(fn, 4s)
#define fs_initcall_sync(fn)		__define_initcall(fn, 5s)
#define device_initcall_sync(fn)	__define_initcall(fn, 6s)
#define late_initcall_sync(fn)		__define_initcall(fn, 7s)
```

* `module_init`

另外，值得一提的是在[include/linux/module.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/module.h#L85)文件汇总定义`module_init`宏，如下：

```C
#define module_init(x)	__initcall(x);
```

`__initcall`宏在[include/linux/init.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/init.h#L234)中定义，设置为`device_initcall`。如下：

```C
#define __initcall(fn) device_initcall(fn)
```

因此，初始化特定的模块时，如果该模块没有显式地添加到特定的`initcall`类别中，而是使用`module_init()` 宏时，默认情况下添加到设备initcall列表中。

## 2 结束语

在这一部分我们分析了Linux内核中`initcall`机制，Linux内核使用`initcall`机制在初始化阶段进行扩展功能初始化。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
