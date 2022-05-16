# 内核系统调用 （第六部分）

## 0 介绍

系统中的每个进程都使用一定数量的不同资源，如：文件，CPU时间，内存等。

这样的资源不是无限的，每个进程都需要一个工具来管理这些资源。有时候了解特定资源的当前限制或改变限制是很有必要的。在这篇文章中，我们将了解如何获取进程的这些限制，修改这些限制。

我们将从用户空间开始，然后分析在Linux内核中实现过程。

## 1 资源限制的介绍

管理进程资源限制的系统调用主要有三个：

* getrlimit
* setrlimit
* prlimit

`getrlimit`和`setrlimit`允许进程读取和设置系统资源的限制。`prlimit`是对前两个功能的扩展，允许设置和读取指定pid的特定资源。这些函数的定义如下：

```C
int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);
int prlimit(pid_t pid, int resource, const struct rlimit *new_limit,
            struct rlimit *old_limit);
```

前两个函数需要两个参数，`resource`表示资源类型，`rlim`表示软限制和硬限制的组合。限制包括软限制（soft）和硬限制（hard）两种，软限制表示进程资源的实际限制；硬限制为软限制的上限，只能由超级用户设置。因此，软限制不能超过硬限制。

在Linux内核中使用`rlimit`结构来表示限制，如下：

```C
struct rlimit {
	__kernel_ulong_t	rlim_cur;
	__kernel_ulong_t	rlim_max;
};
```

`prlimit`函数需要4个参数，除`resource`参数外，`pid`表示进程的ID，`new_rlim`表示新的限制值，`old_limit`表示当前的限制。

`ulimt`工具调用`prlimit`函数，我们可以通过[strace](https://linux.die.net/man/1/strace)工具来验证。例如：

```bash
~$ strace bash -c 'ulimit -a'
prlimit64(0, RLIMIT_NPROC, NULL, {rlim_cur=31360, rlim_max=31360}) = 0
prlimit64(0, RLIMIT_CORE, NULL, {rlim_cur=0, rlim_max=RLIM64_INFINITY}) = 0
prlimit64(0, RLIMIT_DATA, NULL, {rlim_cur=RLIM64_INFINITY, rlim_max=RLIM64_INFINITY}) = 0
...
...
```

这里我们可以看到`prlimit64`，而不是`prlimit`。这是因为，`strace`显示的底层系统调用而不是库调用。

Linux内核中可用的系统资源列表如下：

| 资源（Resource）   | 描述（Description）
|-------------------|------------------------------------------------------------------------------------------|
| RLIMIT_CPU        | CPU时间限制，以秒为单位                                                                     |
| RLIMIT_FSIZE      | 文件的最大大小                                                                             |
| RLIMIT_DATA       | 进程数据段的最大大小                                                                        |
| RLIMIT_STACK      | 进程堆栈的最大大小                                                                          |
| RLIMIT_CORE       | 进程[core dump](http://man7.org/linux/man-pages/man5/core.5.html)文件的最大大小             |
| RLIMIT_RSS        | 进程地址空间的最大字节数                                                                     |
| RLIMIT_NPROC      | 创建的最大进程数                                                                            |
| RLIMIT_NOFILE     | 打开文件的最大数量                                                                          |
| RLIMIT_MEMLOCK    | 通过[mlock](http://man7.org/linux/man-pages/man2/mlock.2.html)锁定到RAM的最大字节数          |
| RLIMIT_AS         | 虚拟内存的最大字节数                                                                         |
| RLIMIT_LOCKS      | [fcntl](http://man7.org/linux/man-pages/man2/fcntl.2.html)持有[flock](https://linux.die.net/man/1/flock)的最大数量|
| RLIMIT_SIGPENDING | [signals](http://man7.org/linux/man-pages/man7/signal.7.html)队列等待的最大数量              |
| RLIMIT_MSGQUEUE   | [POSIX message queues](http://man7.org/linux/man-pages/man7/mq_overview.7.html)的最大字节数 |
| RLIMIT_NICE       | 进程可以设置的最大[nice](https://linux.die.net/man/1/nice)值                                 |
| RLIMIT_RTPRIO     | 最大实时优先级值                                                                             |
| RLIMIT_RTTIME     | 实时任务调度策略中的任务调度的最大微秒数                                                         |

如果你经常查看开源项目源代码，你会注意到读取或更新资源限制是非常广泛的操作。例如：

在[systemd](https://github.com/systemd/systemd/blob/v250/src/core/main.c#L259)中：

```C
/* Don't limit the coredump size */
(void) setrlimit(RLIMIT_CORE, &RLIMIT_MAKE_CONST(RLIM_INFINITY));
```

现在，我们了解了用户空间中资源限制的相关内容，接下来，我们来分析在Linux内核中的系统调用实现过程。

## 2 资源限制的系统调用实现

`getrlimit`和`setrlimit`系统调用的实现相似。这三个系统调用都调用`do_prlimit`这个核心函数，从用户空间复制或向用户空间复制`rlimit`。

`getrlimit`系统调用在[kernel/sys.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sys.c#L1383)中实现，如下：

```C
SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit value;
	int ret;

	ret = do_prlimit(current, resource, NULL, &value);
	if (!ret)
		ret = copy_to_user(rlim, &value, sizeof(*rlim)) ? -EFAULT : 0;

	return ret;
}
```

`setrlimit`系统调用同样在[kernel/sys.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sys.c#L1653)中实现，如下：

```C
SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit new_rlim;

	if (copy_from_user(&new_rlim, rlim, sizeof(*rlim)))
		return -EFAULT;
	return do_prlimit(current, resource, &new_rlim, NULL);
}
```

`do_prlimit`函数同样在[kernel/sys.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sys.c#L1527)中实现。如下：

```C
int do_prlimit(struct task_struct *tsk, unsigned int resource,
		struct rlimit *new_rlim, struct rlimit *old_rlim)
{
	struct rlimit *rlim;
	int retval = 0;
	...
	...
}
```

`do_prlimit`函数首先检查给定的资源是否有效，无效的情况下返回`-EINVAL`错误。如下：

```C
if (resource >= RLIM_NLIMITS)
	return -EINVAL;
```

如果新的限制不为`NULL`，检查软限制不超过硬限制，如果给定的资源是`RLIMIT_NOFILE`，硬限制不能超过`sysctl_nr_open`的值。`sysctl_nr_open`的值可以通过[procfs](https://en.wikipedia.org/wiki/Procfs)查看。如下：

```bash
~$ cat /proc/sys/fs/nr_open 
1048576
```

在经过上面的检查后，我们锁定`tasklist`确保在我们更新给定资源的限制时，信号处理相关内容不会被破坏。我们这么做目的是因为`prlimit`系统调用允许我们通过指定`PID`更新另外任务的限制。如下：

```C
	read_lock(&tasklist_lock);
	...
	...
	...
	read_unlock(&tasklist_lock);
```

由于任务列表被锁定，我们采用`rlimit`负责给定进程的给定资源限制的实例，如下：

```C
rlim = tsk->signal->rlim + resource;
```

`tsk->signal->rlim`是个`struct rlimit`结构体的数组，在[include/linux/sched/signal.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/sched/signal.h#L201)中定义，如下：

```C
struct signal_struct {
	...
	...
	struct rlimit rlim[RLIM_NLIMITS];
	...
	...
} __randomize_layout;
```

如果`new_rlim`有效，我们只需更新它的值；如果`old_rlim`有效，我们填充它。如下：

```C
if (old_rlim)
	*old_rlim = *rlim;
if (new_rlim)
	*rlim = *new_rlim;
```

最后，检查并修改`RLIMIT_CPU`，如下：

```C
if (!retval && new_rlim && resource == RLIMIT_CPU &&
     new_rlim->rlim_cur != RLIM_INFINITY &&
     IS_ENABLED(CONFIG_POSIX_TIMERS))
	update_rlimit_cpu(tsk, new_rlim->rlim_cur);
```

## 3 结束语

本文详细分析了资源限制相关的三个系统调用的实现过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
