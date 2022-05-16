# 同步原语（第一部分）

## 0 介绍

从本节开始将介绍Linux内核中[同步原语](https://en.wikipedia.org/wiki/Synchronization_%28computer_science%29)的概念。像往常一样，我们会尝试去概括地了解什么是`同步原语`。同步原语是一种软件机制，提供了两个或者多个[并行](https://en.wikipedia.org/wiki/Parallel_computing)进程或者线程在不同时刻执行一段相同的代码段的能力。例如下面的代码片段：

```C
mutex_lock(&clocksource_mutex);
...
...
clocksource_enqueue(cs);
clocksource_enqueue_watchdog(cs);
...
...
mutex_unlock(&clocksource_mutex);
```

上面的代码来自于[kernel/time/clocksource.c](https://github.com/torvalds/linux/blob/v5.4/kernel/time/clocksource.c#L918)源文件中的`__clocksource_register_scale`函数，此函数添加给定的[clocksource](https://github.com/torvalds/linux/blob/v5.4/include/linux/clocksource.h#L80)到时钟源列表中。`clocksource_enqueue`函数添加给定时钟源到注册时钟源列表（`clocksource_list`）中。注意这几行代码被`mutex_lock`和`mutex_unlock`这两个函数包围，这两个函数都带有一个参数——在本例中为`clocksource_mutex`。

这两个函数展示了基于[互斥锁(mutex)](https://en.wikipedia.org/wiki/Mutual_exclusion)同步原语的加锁和解锁。在`mutex_lock`执行后，互斥锁持有者执行`mute_unlock`前，将会阻止两个或两个以上线程执行这段代码。换句话说，就是阻止在`clocksource_list`上的并行操作。为什么在这里需要使用`互斥锁`？如果两个并行处理尝试去注册一个时钟源会怎样。正如我们已经知道的那样，在具有最大的等级（在系统中注册的最高频率的时钟源）的列表中选择一个时钟源后，`clocksource_enqueue` 函数立即将给定的时钟源到`clocksource_list`列表：

```C
static void clocksource_enqueue(struct clocksource *cs)
{
	struct list_head *entry = &clocksource_list;
	struct clocksource *tmp;

	list_for_each_entry(tmp, &clocksource_list, list)
		if (tmp->rating >= cs->rating)
			entry = &tmp->list;
	list_add(&cs->list, entry);
}
```

如果两个并行处理尝试同时去执行这个函数，那么这两个处理可能会找到相同的`入口 (entry)`，即：第二个执行`list_add`的处理程序，将会重写第一个线程写入的时钟源。此时就发生了[竞态条件(race condition)](https://en.wikipedia.org/wiki/Race_condition)。

除了这个简答的例子，同步原语在Linux内核无处不在。如果再翻阅之前的章节，就会发现许多地方都使用同步原语。Linux内核提供了一系列不同的同步原语，例如：

* `spinlock`;
* `mutex`;
* `semaphores`;
* `seqlocks`;
* `atomic operations`;
* 等等。

首先我们从`自旋锁 (spinlock)`开始。

## 1 Linux内核中的自旋锁

### 1.1 自旋锁的介绍

自旋锁是一种低级的同步机制，简单来说表示了一个变量可能的两个状态：`acquired`和 `released`。

每一个想要获取`自旋锁`的处理，必须为这个变量写入一个表示`自旋锁获取 (spinlock acquire)`状态的值，并且为这个变量写入`锁释放 (spinlock released)`状态。如果一个处理程序尝试执行被`自旋锁`保护的代码，在占有锁的处理程序释放掉前，这些代码将会被锁住。这种情况下，所有相关的操作必须是
[原子的(atomic)](https://en.wikipedia.org/wiki/Linearizability)，以防出现[竞态条件](https://en.wikipedia.org/wiki/Race_condition)状态。

### 1.2 自旋锁的定义

`自旋锁`在Linux内核中广泛地使用，使用`spinlock_t`类型来表示，`spinlock_t`在[include/linux/spinlock_types.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock_types.h#L61)中定义，如下：

```C
typedef struct spinlock {
	union {
		struct raw_spinlock rlock;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
		struct {
			u8 __padding[LOCK_PADSIZE];
			struct lockdep_map dep_map;
		};
#endif
	};
} spinlock_t;
```

可以看出，它的实现依赖于`CONFIG_DEBUG_LOCK_ALLOC`内核配置选项。现在我们先跳过这一块，在本文的最后来分析所有调试相关的事情。所以，如果 `CONFIG_DEBUG_LOCK_ALLOC`内核配置选项不可用，那么`spinlock_t`只包含一个`union`，如下：

```C
typedef struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
} spinlock_t;
```

`raw_spinlock`结构表示`普通 (normal)` 自旋锁的实现，同样在[include/linux/spinlock_types.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock_types.h#L20)中定义，如下：

```C
typedef struct raw_spinlock {
	arch_spinlock_t raw_lock;
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned int magic, owner_cpu;
	void *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} raw_spinlock_t;
```

其中`arch_spinlock_t`表示基于特定架构的`自旋锁`实现。正如我们上面提到的，我们先跳过调试相关内核配置选项。`arch_spinlock_t`类型基于`CONFIG_SMP`内核配置选项，如下：

```C
#if defined(CONFIG_SMP)
# include <asm/spinlock_types.h>
#else
# include <linux/spinlock_types_up.h>
#endif
```

在`CONFIG_SMP`开启的情况下，`arch_spinlock_t`在[include/asm-generic/qspinlock_types.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/qspinlock_types.h#L22)头文件中定义，如下：

```C
typedef struct qspinlock {
	union {
		atomic_t val;
#ifdef __LITTLE_ENDIAN
		struct {
			u8	locked;
			u8	pending;
		};
		struct {
			u16	locked_pending;
			u16	tail;
		};
#else
		struct {
			u16	tail;
			u16	locked_pending;
		};
		struct {
			u8	reserved[2];
			u8	pending;
			u8	locked;
		};
#endif
	};
} arch_spinlock_t;
```

在`CONFIG_SMP`禁用的情况下，`arch_spinlock_t`在[include/linux/spinlock_types_up.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock_types_up.h#L17)头文件中定义，如下：

```C
typedef struct {
	volatile unsigned int slock;
} arch_spinlock_t;
```

### 1.3 自旋锁的主要操作

现在，我们先看看关于自旋锁的操作，Linux内核在`自旋锁`上提供的主要操作如下：

* `spin_lock_init` —— 初始化自旋锁；
* `spin_lock` —— 获取给定的`自旋锁`；
* `spin_lock_bh` —— 禁止软件[中断](https://en.wikipedia.org/wiki/Interrupt)并且获取给定的`自旋锁`。
* `spin_lock_irqsave` 和 `spin_lock_irq` —— 禁止本地处理器上的中断，并且保存／不保存之前的中断状态的`标识 (flags)`；
* `spin_unlock` —— 释放给定的`自旋锁`;
* `spin_unlock_bh` —— 释放给定的`自旋锁`并且启用软件中断；
* `spin_is_locked` - 返回给定的`自旋锁`的状态；
* 等等。

这些API接口在[include/linux/spinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock.h#L330)头文件中定义，具体实现依赖于 `CONFIG_SMP`内核配置参数，如下：

```C
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
# include <linux/spinlock_api_smp.h>
#else
# include <linux/spinlock_api_up.h>
#endif
```

如果在Linux内核中启用[SMP](https://en.wikipedia.org/wiki/Symmetric_multiprocessing)，那么与`arch_spinlock_t`相关宏就在[include/linux/spinlock_api_smp.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock_api_smp.h)头文件中定义；否则在
[include/linux/spinlock_api_up.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock_api_up.h)头文件中定义。
我们只关注`SMP`启用的情况。

### 1.4 自旋锁初始化

接下来，我们来看看这些操作的实现过程，首先来看看`spin_lock_init`宏的实现，在[include/linux/spinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock.h#L330)头文件中定义，如下：

```C
#define spin_lock_init(_lock)				\
do {							\
	spinlock_check(_lock);				\
	raw_spin_lock_init(&(_lock)->rlock);		\
} while (0)
```

可以看到，`spin_lock_init`宏需要一个`自旋锁`参数，执行两步操作：检查给定的`自旋锁`和执行`raw_spin_lock_init`。`spinlock_check`的实现相当简单，仅仅返回`自旋锁`的`raw_spinlock_t`，来确保我们获得`正常 (normal)`原生的自旋锁：

```C
static __always_inline raw_spinlock_t *spinlock_check(spinlock_t *lock)
{
	return &lock->rlock;
}
```

`raw_spin_lock_init`宏用`__RAW_SPIN_LOCK_UNLOCKED`的值赋值给给定的`raw_spinlock_t`，如下：

```C
# define raw_spin_lock_init(lock)				\
	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); } while (0)
```

我们可以从`__RAW_SPIN_LOCK_UNLOCKED`宏的名称可以知道，这个宏为给定的`自旋锁`执行初始化操作，并且将锁设置为`释放 (released)`状态。宏在 [include/linux/spinlock_types.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock_types.h#L56)头文件中定义，如下：

```C
#define __RAW_SPIN_LOCK_INITIALIZER(lockname)	\
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	SPIN_DEP_MAP_INIT(lockname) }

#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)
```

正如之前所写的一样，我们不考虑同步原语中调试相关的内容。在本例中也不考虑`SPIN_DEBUG_INIT`和`SPIN_DEP_MAP_INIT`宏。于是 `__RAW_SPINLOCK_UNLOCKED`宏被扩展成：

```C
*(&(_lock)->rlock) = __ARCH_SPIN_LOCK_UNLOCKED;
```

在`x86_64`架构下`__ARCH_SPIN_LOCK_UNLOCKED`宏定义为：

```C
#define	__ARCH_SPIN_LOCK_UNLOCKED	{ { .val = ATOMIC_INIT(0) } }
```

因此，在`spin_lock_init`宏扩展之后，给定的`自旋锁`将会初始化并且处于`解锁 (unlocked)`状态。

### 1.4 自旋锁加锁

现在我们了解了如何去初始化一个`自旋锁`，接下来，我们来看看Linux内核为`自旋锁`的操作提供的[API](https://en.wikipedia.org/wiki/Application_programming_interface)。首先是`spin_lock`函数，允许我们`获取`自旋锁：

```C
static __always_inline void spin_lock(spinlock_t *lock)
{
	raw_spin_lock(&lock->rlock);
}
```

`raw_spin_lock` 宏定义在同一个头文件中，扩展为`_raw_spin_lock`函数的调用：

```C
#define raw_spin_lock(lock)	_raw_spin_lock(lock)
```

`_raw_spin_lock`在[include/linux/spinlock_api_smp.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock_api_smp.h#L22)定义，依赖于`CONFIG_INLINE_SPIN_LOCK`内核配置选项，启用的情况下如下：

```C
#ifdef CONFIG_INLINE_SPIN_LOCK
#define _raw_spin_lock(lock) __raw_spin_lock(lock)
#endif
```

否则，在[kernel/locking/spinlock.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/spinlock.c#L148)中实现，如下：

```C
#ifndef CONFIG_INLINE_SPIN_LOCK
void __lockfunc _raw_spin_lock(raw_spinlock_t *lock)
{
	__raw_spin_lock(lock);
}
EXPORT_SYMBOL(_raw_spin_lock);
#endif
```

这两种方式最终调用`__raw_spin_lock`函数，`__raw_spin_lock`函数在[include/linux/spinlock_api_smp.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock_api_smp.h#L139)中实现，如下:

```C
static inline void __raw_spin_lock(raw_spinlock_t *lock)
{
	preempt_disable();
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}
```

可以看到，我们首先调用[include/linux/preempt.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/preempt.h#L242)中的`preempt_disable`宏禁用[抢占](https://en.wikipedia.org/wiki/Preemption_%28computing%29)。当我们将要解开给定的`自旋锁`，抢占将会再次启用：

```C
static inline void __raw_spin_unlock(raw_spinlock_t *lock)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	preempt_enable();
}
```

`spin_acquire`宏在[include/linux/lockdep.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/lockdep.h#L592)中定义，如下：

```C
#define lock_acquire_exclusive(l, s, t, n, i)		lock_acquire(l, s, t, 0, 1, n, i)
#define spin_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
```

`lock_acquire`函数在[kernel/locking/lockdep.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/lockdep.c#L4473)中实现，如下：

```C
void lock_acquire(struct lockdep_map *lock, unsigned int subclass,
			  int trylock, int read, int check,
			  struct lockdep_map *nest_lock, unsigned long ip)
{
	unsigned long flags;

	if (unlikely(current->lockdep_recursion))
		return;

	raw_local_irq_save(flags);
	check_flags(flags);

	current->lockdep_recursion = 1;
	trace_lock_acquire(lock, subclass, trylock, read, check, nest_lock, ip);
	__lock_acquire(lock, subclass, trylock, read, check,
		       irqs_disabled_flags(flags), nest_lock, ip, 0, 0);
	current->lockdep_recursion = 0;
	raw_local_irq_restore(flags);
}
```

就像之前所写的，我们不考虑这些调试或跟踪相关的东西。`lock_acquire`函数主要是通过 `raw_local_irq_save`宏调用禁用硬件中断，因为给定的自旋锁可能在启用硬件中断的情况下获得。以这样的方式获取的话程序将不会被抢占。注意在`lock_acquire`函数结束时使用`raw_local_irq_restore`宏再次启动硬件中断。主要工作在`__lock_acquire`函数中，这个函数同样在[kernel/locking/lockdep.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/lockdep.c#L3812)文件中。`__lock_acquire`函数看起来很大，但该函数和Linux内核[锁验证器 (lock validator)](https://github.com/torvalds/linux/blob/v5.4/Documentation/locking/lockdep-design.rst)密切相关，而这也不是此部分的主题。

现在我们返回`__raw_spin_lock`函数，我们发现它最后包含了下面的定义：

```C
LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
```

`LOCK_CONTENDED`宏在[include/linux/lockdep.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/lockdep.h#L517)头文件中，其实现依赖于`CONFIG_LOCK_STAT`内核配置选项，在开启的情况进行相关统计；没有开启的情况下，定义如下：

```C
#define LOCK_CONTENDED(_lock, try, lock) \
	lock(_lock)
```

在本例中，`lock`就是[include/linux/spinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/spinlock.h#L178)头文件中的 `do_raw_spin_lock`，而`_lock`就是给定的 `raw_spinlock_t`。如下：

```C
static inline void do_raw_spin_lock(raw_spinlock_t *lock) __acquires(lock)
{
	__acquire(lock);
	arch_spin_lock(&lock->raw_lock);
	mmiowb_spin_lock();
}
```

`__acquire`只是[稀疏(sparse)](https://en.wikipedia.org/wiki/Sparse)相关的宏，我们现在对它不感兴趣。`arch_spin_lock`宏在[include/asm-generic/qspinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/qspinlock.h#L112)头文件中定义，如下：

```C
#define arch_spin_lock(l)		queued_spin_lock(l)
```

我们先停留在此。在下一部分中，我们将深入探讨队列自旋锁的概念和工作原理。

## 2 结束语

Linux内核中的同步原语的第一部分到此结束。在这一部分中，我们遇见了Linux内核提供的第一个同步原语`自旋锁`。下一部分将会继续深入这个有趣的主题，并会了解到其他`同步`相关的知识。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
