# 同步原语（第四部分）

## 0 介绍

在前面部分中我们了解了Linux内核中的不同类型的`自旋锁`和`信号量`的实现过程。在本文我们即将了解Linux内核同步原语中的[互斥量](https://en.wikipedia.org/wiki/Mutual_exclusion)的实现过程。

## 1 互斥量的介绍

在前一部分中我们已经熟悉了`信号量`的同步原语。在信号量中保存有关锁的状态和锁的等待列表。根据信号量中的`count`字段的值，可提供对一个资源的多个任务的访问。[互斥量](https://en.wikipedia.org/wiki/Mutual_exclusion)和[信号量](https://en.wikipedia.org/wiki/Semaphore_(programming))的概念非常相似，但有一些不同之处。互斥量比信号量具有更严格的语义，与信号量不同，互斥量一次只能被一个进程持有，并且只有互斥量的持有者才能释放或解锁。API的实现也有所差异，信号量会强制重新调度等待列表中的任务，而互斥量可以避免这个情况，从而避免了高昂的上下文切换。

## 2 互斥量的API

### 2.1 互斥量的定义

互斥量在Linux内核中使用`mutex`结构表示，在[include/linux/mutex.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/mutex.h#L53)中定义，如下：

```C
struct mutex {
	atomic_long_t		owner;
	spinlock_t		wait_lock;
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
	struct optimistic_spin_queue osq; /* Spinner MCS lock */
#endif
	struct list_head	wait_list;
#ifdef CONFIG_DEBUG_MUTEXES
	void			*magic;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
};
```

这个结构的字段说明如下：

* `owner` -- 获取锁的进程；
* `wait_lock` -- 互斥量使用的自旋锁；
* `wait_list` -- 等待的进程列表；
* `osq` -- 依赖于`CONFIG_MUTEX_SPIN_ON_OWNER`内核配置选项，用于优化自选；
* `magic` -- 依赖于`CONFIG_DEBUG_MUTEXES`内核配置选项，存储互斥量调试相关信息；
* `dep_map` -- 依赖于`CONFIG_DEBUG_LOCK_ALLOC`内核配置选项，用于Linux内核锁验证器。
  
其中，`owner`字段包含当前获取锁的`task_struct`的任务结构体指针，`NULL`表示互斥量没有被获取。由于`task_struct`结构至少以 `L1_CACHE_BYTES` 字节对齐，因此一些低比特用来存储额外的状态。`bit0`表示是否为等待者；`bit1`表示解锁时是否交给上一个等待者； `bit2`表示已完成交接，等待获取。相关状态在[kernel/locking/mutex.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/mutex.c#L62)中定义，如下：

```C
#define MUTEX_FLAG_WAITERS	0x01
#define MUTEX_FLAG_HANDOFF	0x02
#define MUTEX_FLAG_PICKUP	0x04

#define MUTEX_FLAGS		0x07
```

### 2.2 互斥量的初始化

在前面我们描述了`互斥量`在Linux内核中表示的结构，接下来，我们需要分析互斥量的API，和互斥量相关的API在[include/linux/mutex.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/mutex.h#L165)中。和往常一样，在考虑如何获取和释放互斥量之前，我们需要知道如何初始化一个`互斥量`。Linux内核提供了两个的初始函数，允许`静态`和`动态`两种方式来初始化一个`互斥量`。

我们来看看第一个种初始化静态`互斥量`，使用`DEFINE_MUTEX`宏来静态初始化`互斥量`，如下：

```C
#define __MUTEX_INITIALIZER(lockname) \
		{ .owner = ATOMIC_LONG_INIT(0) \
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }

#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
```

可以看到，`DEFINE_MUTEX`宏展开`互斥量`结构体的定义，并通过`__MUTEX_INITIALIZER`宏初始化。`__MUTEX_INITIALIZER`宏传入了`互斥量`结构体并初始化这个结构体的各个字段。使用`ATOMIC_LONG_INIT`宏初始化`owner`字段为0；`wait_lock`的自旋锁初始化为未锁定状态；`wait_list`初始化为空链表。

第二种初始化`互斥量`的方式是通过`mutex_init`函数来动态初始化。这个函数是在[include/linux/mutex.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/mutex.h#L104)头文件中定义，如下：

```C
#define mutex_init(mutex)						\
do {									\
	static struct lock_class_key __key;				\
									\
	__mutex_init((mutex), #mutex, &__key);				\
} while (0)
```

这个函数的实现很简单，在定义了`lock_class_key`后，调用`__mutex_init`函数。`__mutex_init`函数在[kernel/locking/mutex.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/mutex.c#L40)中实现，如下：

```C
void
__mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
	atomic_long_set(&lock->owner, 0);
	spin_lock_init(&lock->wait_lock);
	INIT_LIST_HEAD(&lock->wait_list);
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
	osq_lock_init(&lock->osq);
#endif

	debug_mutex_init(lock, name, key);
}
EXPORT_SYMBOL(__mutex_init);
```

可以看到，`__mutex_init`函数需要三个参数：`lock` -- 互斥量；`name` -- 调试用的互斥量名称；`key` -- 锁验证器的秘钥。`__mutex_init`的实现也非常简单，设置`lock`互斥量的相关字段。调用`atomic_long_set`函数以原子的方式设置`owner`；调用`spin_lock_init`函数初始化自旋锁位解锁状态；初始化`wait_list`为空队列。

在此之后，调用`osq_lock_init`函数初始化乐观队列锁，将乐观队列锁的尾部设置为解锁状态，如下：

```C
static inline void osq_lock_init(struct optimistic_spin_queue *lock)
{
	atomic_set(&lock->tail, OSQ_UNLOCKED_VAL);
}
```

在`__mutex_init`函数的最后，调用`debug_mutex_init`函数设置相关调试信息。

### 2.3 互斥量的加锁实现

Linux内核中在[include/linux/mutex.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/mutex.h#L165)文件中提供了下面几种`互斥量`加锁的API：

```C
extern void mutex_lock(struct mutex *lock);
extern int __must_check mutex_lock_interruptible(struct mutex *lock);
extern int __must_check mutex_lock_killable(struct mutex *lock);
extern void mutex_lock_io(struct mutex *lock);
extern int mutex_trylock(struct mutex *lock);
```

`mutex_lock`用来获取`互斥量`。`mutex_lock_interruptible` 函数和`信号量`的`down_interruptible`类似，试图去获取一个`互斥量`，如果成功获取后，表示获取到锁，否则，任务将切换到阻塞状态，即，任务标志的`TASK_INTERRUPTIBLE` 标志将会设置。

同样，`mutex_lock_killable`函数和`mutex_lock_interruptible`函数提供类似的功能，它设置当前进程的`TASK_KILLABLE`标志。

`mutex_lock_io`函数在获取互斥量的同时，将进程标记为等待I/O。

`mutex_trylock`函数和`spin_trylock`类似，尝试获取`互斥量`，返回值表示是否获取到互斥量。

我们从`mutex_lock`函数开始。这个函数是在[kernel/locking/mutex.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/mutex.c#L279)文件中实现，如下：

```C
void __sched mutex_lock(struct mutex *lock)
{
	might_sleep();

	if (!__mutex_trylock_fast(lock))
		__mutex_lock_slowpath(lock);
}
EXPORT_SYMBOL(mutex_lock);
```

`might_sleep`宏在[include/linux/kernel.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/kernel.h#L228)中定义，该宏的实现依赖于`CONFIG_DEBUG_ATOMIC_SLEEP`内核配置选项，在开启的情况在原子上下文中执行时打印堆栈跟踪信息，用于调试。

之后，调用`__mutex_trylock_fast`函数，这个函数尝试快速的方式获取互斥量，同样在[kernel/locking/mutex.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/mutex.c#L177)文件中实现，如下：

```C
static __always_inline bool __mutex_trylock_fast(struct mutex *lock)
{
	unsigned long curr = (unsigned long)current;
	unsigned long zero = 0UL;

	if (atomic_long_try_cmpxchg_acquire(&lock->owner, &zero, curr))
		return true;

	return false;
}
```

可以看到，`__mutex_trylock_fast`函数调用 `atomic_long_try_cmpxchg_acquire` 函数，调用`cmpxchg`指令尝试在`owner`字段为`0`情况设置`curr`。成功设置后，返回`true`；否则返回`false`。

现在回到`mutex_lock`函数，在`__mutex_trylock_fast`函数返回失败的情况下，调用 `__mutex_lock_slowpath` 函数处理需要等待的情况。`__mutex_lock_slowpath`函数调用`__mutex_lock`函数，进而调用`__mutex_lock_common`函数。如下：

```C
static noinline void __sched
__mutex_lock_slowpath(struct mutex *lock)
{
	__mutex_lock(lock, TASK_UNINTERRUPTIBLE, 0, NULL, _RET_IP_);
}

static int __sched
__mutex_lock(struct mutex *lock, long state, unsigned int subclass,
	     struct lockdep_map *nest_lock, unsigned long ip)
{
	return __mutex_lock_common(lock, state, subclass, nest_lock, ip, NULL, false);
}
```

`__mutex_lock_common`函数同样在[kernel/locking/mutex.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/mutex.c#L925)文件中实现，如下：

```C
static __always_inline int __sched
__mutex_lock_common(struct mutex *lock, long state, unsigned int subclass,
		    struct lockdep_map *nest_lock, unsigned long ip,
		    struct ww_acquire_ctx *ww_ctx, const bool use_ww_ctx)
{
	struct mutex_waiter waiter;
	struct ww_mutex *ww;
	int ret;
	...
	...
	...
}
```

`__mutex_lock_common`函数会额外处理`ww_acquire_ctx`的情况，`__mutex_lock`中设置为`NULL`，我们不考虑这种情况。在我们继续分析之前，先分析在 `__mutex_lock_common` 中频繁出现的`__mutex_trylock`函数。根据名称我们知道该函数尝试获取锁，实现如下：

```C
static inline bool __mutex_trylock(struct mutex *lock)
{
	return !__mutex_trylock_or_owner(lock);
}

static inline struct task_struct *__mutex_trylock_or_owner(struct mutex *lock)
{
	unsigned long owner, curr = (unsigned long)current;

	owner = atomic_long_read(&lock->owner);
	for (;;) { /* must loop, can race against a flag */
		unsigned long old, flags = __owner_flags(owner);
		unsigned long task = owner & ~MUTEX_FLAGS;
		if (task) {
			if (likely(task != curr))
				break;
			if (likely(!(flags & MUTEX_FLAG_PICKUP)))
				break;
			flags &= ~MUTEX_FLAG_PICKUP;
		}
		...
		...
		flags &= ~MUTEX_FLAG_HANDOFF;
		old = atomic_long_cmpxchg_acquire(&lock->owner, owner, curr | flags);
		if (old == owner)
			return NULL;

		owner = old;
	}
	return __owner_task(owner);
}
```

根据代码可以看到，`__mutex_trylock`函数在`__mutex_trylock_or_owner`函数返回`NULL`时，表示获取到自旋锁。

接下来，我们分析`__mutex_lock_common`函数的实现过程，该函数从调用`preempt_disable()`宏禁用抢占开始，会经过下面几个过程：

* 第一次快速检查

首先，我们调用`__mutex_trylock`函数和`mutex_optimistic_spin`函数检查是否获取到互斥量，在成功获取后，调用`preempt_enable()`宏开启抢占后返回。如下：

```C
	if (__mutex_trylock(lock) ||
	    mutex_optimistic_spin(lock, ww_ctx, NULL)) {
		lock_acquired(&lock->dep_map, ip);
		if (ww_ctx)
			ww_mutex_set_context_fastpath(ww, ww_ctx);
		preempt_enable();
		return 0;
	}
```

* 第二次快速检查

在第一次快速检查失败后，调用`spin_lock`函数获取`互斥量`的自旋锁后，调用`__mutex_trylock`函数检查是否获取到互斥量。成功获取到后，跳转到`skip_wait`标签，进入清理阶段。如下：

```C
	spin_lock(&lock->wait_lock);
	if (__mutex_trylock(lock)) {
		if (ww_ctx)
			__ww_mutex_check_waiters(lock, ww_ctx);

		goto skip_wait;
	}
```

* 等待阶段

在等待阶段，在不采用`use_ww_ctx`的情况下，我们将当前任务添加到互斥量的等待列表中，如下：

```C
	if (!use_ww_ctx) {
		__mutex_add_waiter(lock, &waiter, &lock->wait_list);

	waiter.task = current;
```

`waiter`是`mutex_waiter`的结构，在[include/linux/mutex.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/mutex.h#L72)中定义，如下：

```C
struct mutex_waiter {
	struct list_head	list;
	struct task_struct	*task;
	struct ww_acquire_ctx	*ww_ctx;
#ifdef CONFIG_DEBUG_MUTEXES
	void			*magic;
#endif
};
```

接下来，设置任务状态后，进入循环判断，在循环中尝试获取互斥量。如下：

```C
	set_current_state(state);
	for (;;) {
		bool first;

		if (__mutex_trylock(lock))
			goto acquired;

		if (signal_pending_state(state, current)) {
			ret = -EINTR;
			goto err;
		}
		...
		...
		spin_unlock(&lock->wait_lock);
		schedule_preempt_disabled();

		first = __mutex_waiter_is_first(lock, &waiter);
		if (first)
			__mutex_set_flag(lock, MUTEX_FLAG_HANDOFF);

		set_current_state(state);

		if (__mutex_trylock(lock) ||
		    (first && mutex_optimistic_spin(lock, ww_ctx, &waiter)))
			break;

		spin_lock(&lock->wait_lock);
	}
```

可以看到，首先调用`__mutex_trylock`尝试获取互斥量（此时，可能会调用`mutex_unlock`函数释放互斥量），获取成功后跳转到`acquired` 标签，进入获取互斥量阶段；接下来，调用`signal_pending_state`函数检查任务状态，出错时，跳转到`err`标签，进行错误处理；接下来，我们释放自旋锁，调用`schedule_preempt_disabled` 等待下次任务调度；在调度返回后，检查是否是第一个等待者，如果是设置`MUTEX_FLAG_HANDOFF` 标记；在此之后，调用`__mutex_trylock`检查是否获取到互斥量，在获取后退出循环，否则，进行下一次等待。

* 获取互斥量阶段

在获取互斥量后，设置任务为运行状态，将当前任务从等待列表中移除。如下：

```C
acquired:
	__set_current_state(TASK_RUNNING);
	...
	__mutex_remove_waiter(lock, &waiter);
	debug_mutex_free_waiter(&waiter);
```

* 清理阶段

在获取互斥量后，进行最后的清理工作，包括：释放自旋锁，启用抢占。如下：

```C
skip_wait:
	lock_acquired(&lock->dep_map, ip);

	if (ww_ctx)
		ww_mutex_lock_acquired(ww, ww_ctx);

	spin_unlock(&lock->wait_lock);
	preempt_enable();
	return 0;
```

* 错误阶段

这个阶段，同获取到互斥量的操作类似，从等待列表中移除当前任务、释放自旋锁，启用抢占等。但返回值是对应的错误码。如下：

```C
err:
	__set_current_state(TASK_RUNNING);
	__mutex_remove_waiter(lock, &waiter);
err_early_kill:
	spin_unlock(&lock->wait_lock);
	debug_mutex_free_waiter(&waiter);
	mutex_release(&lock->dep_map, 1, ip);
	preempt_enable();
	return ret;
```

### 2.4 互斥量的解锁实现

在上面我们分析了互斥量的加锁实现，现在我们分析其解锁实现。互斥量的解锁通过`mutex_unlock`函数来实现，如下：

```C
void __sched mutex_unlock(struct mutex *lock)
{
#ifndef CONFIG_DEBUG_LOCK_ALLOC
	if (__mutex_unlock_fast(lock))
		return;
#endif
	__mutex_unlock_slowpath(lock, _RET_IP_);
}
EXPORT_SYMBOL(mutex_unlock);
```

可以看到，在内核选项`CONFIG_DEBUG_LOCK_ALLOC`没有定义的情况，支持调用`__mutex_unlock_fast`进行快速解锁。如下：

```C
static __always_inline bool __mutex_unlock_fast(struct mutex *lock)
{
	unsigned long curr = (unsigned long)current;
	if (atomic_long_cmpxchg_release(&lock->owner, curr, 0UL) == curr)
		return true;
	return false;
}
```

`__mutex_unlock_fast`函数在`current`占用的情况下（即，`owner` 为 `current` ），可以进行快速解锁。

在快速解锁失败或禁用的的情况下，调用`__mutex_unlock_slowpath`函数进行慢路径解锁。如下：

```C
static noinline void __sched __mutex_unlock_slowpath(struct mutex *lock, unsigned long ip)
{
	struct task_struct *next = NULL;
	DEFINE_WAKE_Q(wake_q);
	unsigned long owner;
	...
	...
}
```

* 快速释放互斥量

获取`owner`后检查`flags`状态，除`MUTEX_FLAG_HANDOFF`外的其他状态，检查快速释放，如下：

```C
	owner = atomic_long_read(&lock->owner);
	for (;;) {
		unsigned long old;
		if (owner & MUTEX_FLAG_HANDOFF)
			break;
		old = atomic_long_cmpxchg_release(&lock->owner, owner,
						  __owner_flags(owner));
		if (old == owner) {
			if (owner & MUTEX_FLAG_WAITERS)
				break;

			return;
		}
		owner = old;
	}
```

`flags`存在 `MUTEX_FLAG_HANDOFF` 标记位时，直接退出循环。在通过`cmpxchg` 指令比较交换后，`owner` 不存在 `MUTEX_FLAG_WAITERS` 标记位时，认为快速释放。

* 正常释放互斥量

接下来，进行正常释放流程。如下：

```C
	spin_lock(&lock->wait_lock);
	debug_mutex_unlock(lock);
	if (!list_empty(&lock->wait_list)) {
		/* get the first entry from the wait-list: */
		struct mutex_waiter *waiter =
			list_first_entry(&lock->wait_list,
					 struct mutex_waiter, list);
		next = waiter->task;
		debug_mutex_wake_waiter(lock, waiter);
		wake_q_add(&wake_q, next);
	}
	if (owner & MUTEX_FLAG_HANDOFF)
		__mutex_handoff(lock, next);
	spin_unlock(&lock->wait_lock);

	wake_up_q(&wake_q);
```

获取互斥量的自旋锁后，如果等待的队列不为空，等待的队列中获取第一个条目，调用`wake_q_add`函数添加到唤醒队列中，最终调用`wake_up_q`函数进行唤醒。

如果存在 `MUTEX_FLAG_HANDOFF` 标记位时，调用`__mutex_handoff` 函数，将互斥量的所有者移交给`next`任务。

## 3 结束语

在这一部分我们分析了Linux内核中另一个同步原语 -- `互斥量`。互斥量表示二进制信号量，但它的实现和`信号量`不同。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
