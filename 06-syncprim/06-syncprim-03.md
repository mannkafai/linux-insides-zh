# 同步原语（第三部分）

## 0 介绍

在前面两部分中我们了解了Linux内核中的`自旋锁`和`队列自旋锁`的实现过程。在本文我们即将了解Linux内核同步原语中的[信号量](https://en.wikipedia.org/wiki/Semaphore_%28programming%29)的实现过程。

## 1 信号量的介绍

`自旋锁`在获取后可以保护共享资源不能被多个进程修改，尝试获取当前锁的其他进程被停止（也称为`原地等待`）。自旋锁为了避免[死锁](https://en.wikipedia.org/wiki/Deadlock)禁用了[抢占](https://en.wikipedia.org/wiki/Preemption_(computing))，因此不允许[上下文切换](https://en.wikipedia.org/wiki/Context_switch)。因此，自旋锁只适用于很短时间的操作，否则其他进程累计的繁忙等待会导致操作效率极其低下。对于需要获取较长时间的锁，我们转向`信号量`。

[信号量](https://en.wikipedia.org/wiki/Semaphore_%28programming%29)对于可能需要长时间持有锁来说是一个很好的解决方案。从另一个方面看，这个机制对于需要短期持有锁的应用并不是最优。为了理解这个问题，我们需要知道什么是 `信号量`。

和通常的同步原语一样，`信号量`是基于变量的。这个变量可以变大或者减少，变量的状态代表了获取锁的能力。注意这个变量的值并不限于`0`和`1`。根据变量的值，可以分为两种类型的信号量：`二值信号量`和`普通信号量`。第一种`二值信号量`的值可以为`1`或者`0`。第二种`普通信号量`的值可以为任何非负数。如果`信号量`的值大于`1`，那么它被叫做`计数信号量`，并且它允许多于`1`个进程获取锁。这种机制允许我们记录现有的资源，而`自旋锁`只允许一个进程获取锁。除此之外，另外一个重要的点是`信号量`允许进入睡眠状态，当某进程在等待一个被其他进程获取的锁时，[调度器](https://en.wikipedia.org/wiki/Scheduling_%28computing%29)也许会切换别的进程。

## 2 信号量的API

我们了解一些`信号量`的理论知识，接下来，我们来看看它在Linux内核中是如何实现的。所有`信号量`相关的API都在[include/linux/semaphore.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/semaphore.h)头文件中。

我们看到`信号量`在Linux内核中对应的结构体如下：

```C
struct semaphore {
	raw_spinlock_t		lock;
	unsigned int		count;
	struct list_head	wait_list;
};
```

在Linux内核中，`信号量`结构体由三个字段组成：

* `lock` - 保护`信号量`数据的`自旋锁`;
* `count` - 可用资源的数量;
* `wait_list` - 等待获取锁的进程列表.

### 2.1 信号量的初始化

在我们了解`信号量`API之前，我们需要知道如何初始化一个`信号量`。Linux内核提供了两个的初始函数，允许`静态`和`动态`两种方式来初始化一个`信号量`。

我们来看看第一个种初始化静态`信号量`。我们可以使用`DEFINE_SEMAPHORE`宏来静态初始化`信号量`，如下：

```C
#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}

#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)
```

可以看到，`DEFINE_SEMAPHORE`宏只提供了初始化`二值`信号量的功能。`DEFINE_SEMAPHORE`宏展开到`信号量`结构体的定义，并通过  `__SEMAPHORE_INITIALIZER` 宏初始化。`__SEMAPHORE_INITIALIZER` 宏传入了`信号量`结构体并初始化这个结构体的各个字段。使用 `__RAW_SPIN_LOCK_UNLOCKED` 宏初始化信号量中的`lock`字段，`count` 和`wait_list`是通过现有资源的数量和空链表来初始化。

第二种初始化`信号量`的方式是将`信号量`和可用资源的数量传送给`sema_init`函数。这个函数是在[include/linux/semaphore.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/semaphore.h#L31)头文件中定义，如下：

```C
static inline void sema_init(struct semaphore *sem, int val)
{
	static struct lock_class_key __key;
	*sem = (struct semaphore) __SEMAPHORE_INITIALIZER(*sem, val);
	lockdep_init_map(&sem->lock.dep_map, "semaphore->lock", &__key, 0);
}
```

这个函数的实现很简单，使用我们刚看到的`__SEMAPHORE_INITIALIZER`宏对传入的`信号量`进行初始化。我们将会跳过Linux内核关于[锁验证](https://github.com/torvalds/linux/blob/v5.4/Documentation/locking/lockdep-design.rst)的相关内容。

### 2.2 信号量的加锁实现

现在，我们知道如何初始化一个`信号量`，我们看看如何上锁，Linux内核提供了如下加锁`信号量`的API：

```C
extern void down(struct semaphore *sem);
extern int __must_check down_interruptible(struct semaphore *sem);
extern int __must_check down_killable(struct semaphore *sem);
extern int __must_check down_trylock(struct semaphore *sem);
extern int __must_check down_timeout(struct semaphore *sem, long jiffies);
```

`down`用来获取`信号量`。`down_interruptible`函数试图去获取一个 `信号量`，如果成功获取后，`信号量`的计数就会被减少并且获取锁，否则，任务将切换到阻塞状态，即，任务标志的`TASK_INTERRUPTIBLE` 标志将会设置。`TASK_INTERRUPTIBLE` 标志表示进程可以通过[信号](https://en.wikipedia.org/wiki/Unix_signal)退回到销毁状态。

`down_killable`函数和`down_interruptible`函数提供类似的功能，它设置当前进程的`TASK_KILLABLE`标志。这表示等待的进程可以被杀死信号中断。

`down_trylock`函数和`spin_trylock`函数相似。这个函数试图去获取一个锁，获取失败时立即退出。最后的`down_timeout`函数试图去获取一个锁，当前进程将会被中断进入到等待状态直到可等待时间到期，这个等待的时间是`jiffies`计数。

我们刚刚看了`信号量`API的定义，我们从`down`函数开始。这个函数是在[kernel/locking/semaphore.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/semaphore.c#L53)文件中实现，如下：

```C
void down(struct semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(sem->count > 0))
		sem->count--;
	else
		__down(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);
}
EXPORT_SYMBOL(down);
```

在`down`函数起始处定义的`flags`变量，这个变量将会传入到 `raw_spin_lock_irqsave` 和 `raw_spin_unlock_irqrestore` 宏。这两个宏是在[include/linux/spinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock.h#L247)头文件定义，用来保护当前`信号量`的计数器。这两个宏的作用和`spin_lock`和`spin_unlock`宏相似，只不过这组宏会存储/重置当前中断标志的同时禁止[中断](https://en.wikipedia.org/wiki/Interrupt)。

`down`函数的主要功能在 `raw_spin_lock_irqsave` 和 `raw_spin_unlock_irqrestore` 宏之间的功能来实现的。我们通过将`信号量`的计数器和零对比，如果计数器大于零，我们可以减少这个计数器，这表示我们已经获取了这个锁；否则如果计数器是零，这表示所以的现有资源都已经被占用，我们需要等待以获取这个锁。正如我们看到的那样，`__down`函数将会被调用。

`__down`函数是在[相同](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/semaphore.c#L235)的文件中实现，如下：

```C
static noinline void __sched __down(struct semaphore *sem)
{
	__down_common(sem, TASK_UNINTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
}
```

 `__down`函数仅仅调用了`__down_common`函数，并且传入了三个参数：`sem` -- 信号量, `flag` -- 任务标识; `timeout` -- 等待`信号量`的最长时间.

在我们分析`__down_common`函数之前，注意`__down_interruptible`, `__down_killable` 和 `__down_timeout`的实现也都是基于`__down_common` 函数，如下：

```C
static noinline int __sched __down_interruptible(struct semaphore *sem)
{
	return __down_common(sem, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
}

static noinline int __sched __down_killable(struct semaphore *sem)
{
	return __down_common(sem, TASK_KILLABLE, MAX_SCHEDULE_TIMEOUT);
}

static noinline int __sched __down_timeout(struct semaphore *sem, long timeout)
{
	return __down_common(sem, TASK_UNINTERRUPTIBLE, timeout);
}
```

现在我们来看看`__down_common` 函数的实现。这个函数是在[kernel/locking/semaphore.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/semaphore.c#L204)源文件中定义，如下：

```C
static inline int __sched __down_common(struct semaphore *sem, long state,
								long timeout)
{
	struct semaphore_waiter waiter;
	...
	...
}
```

变量`waiter`表示了一个`semaphore.wait_list`列表的入口，定义如下：

```C
struct semaphore_waiter {
        struct list_head list;
        struct task_struct *task;
        bool up;
};
```

首先，我们将当前进程加入到`wait_list`，并填充`waiter`字段，如下：

```C
	list_add_tail(&waiter.list, &sem->wait_list);
	waiter.task = current;
	waiter.up = false;
```

`current`宏表示当前想获取本地处理器锁的任务。 `current` 宏是在 [arch/x86/include/asm/current.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/current.h#L18)头文件中定义，如下：

```C
#define current get_current()
```

`get_current`函数返回`current_task`变量的值。如下：

```C
DECLARE_PER_CPU(struct task_struct *, current_task);

static __always_inline struct task_struct *get_current(void)
{
	return this_cpu_read_stable(current_task);
}
```

在初始化`waiter`后，下一步我们进入到如下的无限循环中：

```C
	for (;;) {
		if (signal_pending_state(state, current))
			goto interrupted;
		if (unlikely(timeout <= 0))
			goto timed_out;
		__set_current_state(state);
		raw_spin_unlock_irq(&sem->lock);
		timeout = schedule_timeout(timeout);
		raw_spin_lock_irq(&sem->lock);
		if (waiter.up)
			return 0;
	}
```

在之前的代码中我们将`waiter.up`设置为`false`，当`up`没有设置为`true`时，将会一直在这个循环中。这个循环从检查当前的任务是否处于 `pending` 状态开始，即此任务的标志包含 `TASK_INTERRUPTIBLE` 或者 `TASK_WAKEKILL` 标志。当任务在等待获取锁期间，任务可能被[信号](https://en.wikipedia.org/wiki/Unix_signal)中断。`signal_pending_state`函数是在[include/linux/sched/signal.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/sched/signal.h#L362)文件中定义，如下：

```C
static inline int signal_pending_state(long state, struct task_struct *p)
{
	if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL)))
		return 0;
	if (!signal_pending(p))
		return 0;

	return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
}
```

我们先会检测`state`[位掩码](https://en.wikipedia.org/wiki/Mask_%28computing%29)是否包含 `TASK_INTERRUPTIBLE` 或者 `TASK_WAKEKILL` 位，如果不包含这两个位，函数退出。下一步我们检测当前任务是否有挂起信号，如果没有，函数退出。最后我们就检测`state`位掩码的 `TASK_INTERRUPTIBLE` 位。

如果我们任务包含一个挂起信号，`signal_pending_state` 返回后，将会跳转到 `interrupted` 标签，在这个标签中，我们会删除等待锁的列表，然后返回`-EINTR`[错误码](https://en.wikipedia.org/wiki/Errno.h)，如下：

```C
interrupted:
    list_del(&waiter.list);
    return -EINTR;
```

如果一个任务没有挂起信号，我们检测超时时间是否小于等于零，如果是，我们跳转到`timed_out`标签。在这个标签里，我们继续做和`interrupted`一样的事情，从锁等待者中删除任务，返回`-ETIME`错误码，如下：

```C
if (unlikely(timeout <= 0))
    goto timed_out;
...
...
timed_out:
    list_del(&waiter.list);
    return -ETIME;
```

如果一个任务没有挂起信号并且给定的超时也没有过期，当前的任务将会被设置为传入的 `state`，然后调用`schedule_timeout` 函数：

```C
		__set_current_state(state);
		raw_spin_unlock_irq(&sem->lock);
		timeout = schedule_timeout(timeout);
		raw_spin_lock_irq(&sem->lock);
```

`schedule_timeout`函数在[kernel/time/timer.c](https://github.com/torvalds/linux/blob/v5.4/kernel/time/timer.c#L1856)中实现，该函数使当前的任务休眠，直到设置的超时。

这就是关于`__down_common`函数的所有功能。如果一个任务想要获取已经被其它任务获取的锁时，如果它不能被信号中断、设置的超时没有过期或者当前持有锁的任务没有释放时，它将在无限循环中一直循环。

### 2.3 信号量的解锁实现

信号量通过`up`函数来释放。`up`函数和`down`函数同样在[kernel/locking/semaphore.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/semaphore.c#L178)文件中实现，如下：

```C
void up(struct semaphore *sem)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&sem->lock, flags);
	if (likely(list_empty(&sem->wait_list)))
		sem->count++;
	else
		__up(sem);
	raw_spin_unlock_irqrestore(&sem->lock, flags);
}
EXPORT_SYMBOL(up);
```

它看起来和`down`函数相似，通过 `raw_spin_lock_irqsave` 和 `raw_spin_unlock_irqrestore` 宏保存信号量的数据。如果信号量的等待列表为空，我们增加`semaphore`的计数；否则，调用在同一个文件中定义的`__up` 函数，允许列表中的第一个任务获取锁，如下：

```C
static noinline void __sched __up(struct semaphore *sem)
{
	struct semaphore_waiter *waiter = list_first_entry(&sem->wait_list,
						struct semaphore_waiter, list);
	list_del(&waiter->list);
	waiter->up = true;
	wake_up_process(waiter->task);
}
```

我们获取待序列中的第一个任务，将它从列表中删除，将它的`waiter->up`设置为`true`。此时，`__down_common` 函数中的无限循环将会停止。我们在 `__down_common` 函数中调用了 `schedule_timeout` 函数，将当前任务置于睡眠状态直到超时等待。由于我们进程现在可能处于睡眠状态，我们需要唤醒。在`_up`函数的最后调用 `wake_up_process` 函数来唤起等待的任务。

## 3 结束语

在这一部分我们分析了Linux内核中另一个同步原语 -- `信号量`，它用于长时间锁定，并且会导致[上下文切换](https://en.wikipedia.org/wiki/Context_switch)。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
