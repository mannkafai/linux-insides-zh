# 同步原语（第二部分）

## 0 介绍

在第一部分中我们分析了[自旋锁](https://en.wikipedia.org/wiki/Spinlock)的同步原语。我们将继续学习自旋锁的同步原语。在上一部分中我们在普通自旋锁的基础上引入了一种特殊类型 -- `队列自旋锁`。在这个部分我们将尝试理解此概念代表的含义。

我们在上一部分中看到了`自旋锁`的[API](https://en.wikipedia.org/wiki/Application_programming_interface):

* `spin_lock_init` —— 初始化自旋锁；
* `spin_lock` —— 获取给定的`自旋锁`；
* `spin_lock_bh` —— 禁止软件[中断](https://en.wikipedia.org/wiki/Interrupt)并且获取给定的`自旋锁`。
* `spin_lock_irqsave` 和 `spin_lock_irq` —— 禁止本地处理器上的中断，并且保存／不保存之前的中断状态的`标识 (flags)`；
* `spin_unlock` —— 释放给定的`自旋锁`;
* `spin_unlock_bh` —— 释放给定的`自旋锁`并且启用软件中断；
* `spin_is_locked` - 返回给定的`自旋锁`的状态；
* 等等。

而且我们知道所有这些宏最终会调用`arch_*`开头的宏，这些`arch_*`开头的宏在[include/asm-generic/qspinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/qspinlock.h#L109)扩展，如下：

```c
#define arch_spin_is_locked(l)		queued_spin_is_locked(l)
#define arch_spin_is_contended(l)	queued_spin_is_contended(l)
#define arch_spin_value_unlocked(l)	queued_spin_value_unlocked(l)
#define arch_spin_lock(l)		queued_spin_lock(l)
#define arch_spin_trylock(l)		queued_spin_trylock(l)
#define arch_spin_unlock(l)		queued_spin_unlock(l)
```

在我们考虑队列自旋锁和实现他们的API之前，我们首先看下理论部分。

## 1 队列自旋锁的介绍

队列自旋锁是Linux内核中的一种[锁机制](https://en.wikipedia.org/wiki/Lock_%28computer_science%29)，它替代了标准`自旋锁`。至少在[x86_64](https://en.wikipedia.org/wiki/X86-64)架构上进行了替换。如果我们查看内核配置文件 - [kernel/Kconfig.locks](https://github.com/torvalds/linux/blob/v5.4/kernel/Kconfig.locks#L239)，我们将会发现以下配置条目：

```text
config ARCH_USE_QUEUED_SPINLOCKS
	bool

config QUEUED_SPINLOCKS
	def_bool y if ARCH_USE_QUEUED_SPINLOCKS
	depends on SMP
```

这意味着如果`ARCH_USE_QUEUED_SPINLOCKS`启用，默认情况下将启用`CONFIG_QUEUED_SPINLOCKS`内核配置选项。我们在`x86_64`特定内核配置文件[arch/x86/Kconfig](https://github.com/torvalds/linux/blob/v5.4/arch/x86/Kconfig#L95)中，可以看到`ARCH_USE_QUEUED_SPINLOCKS`默认开启：

```text
config X86
    ...
    ...
    ...
    select ARCH_USE_QUEUED_SPINLOCKS
    ...
    ...
    ...
```

在开始考虑什么是队列自旋锁概念之前，让我们看看其他类型的`自旋锁`。首先，我们来看下`正常`自旋锁是如何实现的。通常，`正常`自旋锁的实现是基于[test and set](https://en.wikipedia.org/wiki/Test-and-set)指令。这个指令的工作原则非常简单，该指令写入一个值到内存地址然后从中返回旧值。这些指令在一起是原子操作，即：不可中断的指令。因此，如果第一个线程开始执行这个指令，第二个线程将会等待第一个线程完成指令的执行。基本锁可以在建立在这个机制上，看起来如下所示：

```C
int lock(lock)
{
    while (test_and_set(lock) == 1)
        ;
    return 0;
}

int unlock(lock)
{
    lock=0;

    return lock;
}
```

第一个线程将执行`test_and_set`指令设置`lock`为`1`。当第二个线程调用`lock`函数时，它将在`while`循环中自旋，直到第一个线程调用`unlock`函数将`lock`设置为`0`。这个实现出于性能原因，实现不是很好，该实现至少存在两个问题。第一个问题是该实现可能是非公平的，后面执行的线程可能会先获得锁；第二个问题是所有想要获取锁的线程都必须执行许多原子操作，`test_and_set`对共享内存中的变量执行许多操作，这会导致缓存失效。在加锁时，在缓存中`lock=1`，但释放锁之后，内存中`lock`的值可能不是`1`。

这一部分的主题是`队列自旋锁`。这个方法能够帮助解决上述的两个问题，`队列自旋锁`允许每个处理器在自旋过程使用自己的内存地址。通过研究[MCS](http://www.cs.rochester.edu/~scott/papers/1991_TOCS_synch.pdf)这个基于队列自旋锁的实现，可以很好的理解基于队列自旋锁的基本原则。在了解Linux内核中`队列自旋锁`的实现之前，我们首先来了解`MCS`锁的工作原理。

`MCS`锁的基本理念线程在每个处理器的本地变量上自旋，系统中的每个处理器都拥有这些变量的副本。换句话说，这个概念建立在Linux内核中的`per-cpu`变量概念之上。当第一个线程想要获取锁时，它将自己注册到`队列`中，或者换句话说，因为队列现在是闲置的，线程被添加到特殊的`队列`中并且获取锁。当第二个线程想要在第一个线程释放锁之前获取相同锁，这个线程就会把它自身的锁变量副本添加到这个特殊`队列`中。在这种情况下，第一个线程将包含一个`next`字段指向第二个线程。从这一时刻起，第二个线程会等待直到第一个线程释放它的锁并通知`next`线程这个事件。第一个线程从`队列`中删除，而第二个线程持有该锁。

整个过程示意如下：

空队列：

```text
+---------+
|         |
|  Queue  |
|         |
+---------+
```

第一个线程尝试获取锁：

```text
+---------+     +----------------------------+
|         |     |                            |
|  Queue  |---->| First thread acquired lock |
|         |     |                            |
+---------+     +----------------------------+
```

第二个队列尝试获取锁:

```text
+---------+     +----------------------------------------+     +-------------------------+
|         |     |                                        |     |                         |
|  Queue  |---->|  Second thread waits for first thread  |<----| First thread holds lock |
|         |     |                                        |     |                         |
+---------+     +----------------------------------------+     +-------------------------+
```

伪代码可以描述为：

```C
void lock(...)
{
    lock.next = NULL;
    ancestor = put_lock_to_queue_and_return_ancestor(queue, lock);

    // if we have ancestor, the lock already acquired and we
    // need to wait until it will be released
    if (ancestor)
    {
        lock.locked = 1;
        ancestor.next = lock;

        while (lock.is_locked == true)
            ;
    }

    // in other way we are owner of the lock and may exit
}

void unlock(...)
{
    // do we need to notify somebody or we are alonw in the
    // queue?
    if (lock.next != NULL) {
        // the while loop from the lock() function will be
        // finished
        lock.next.is_locked = false;
        // delete ourself from the queue and exit
        ...
        ...
        ...
        return;
    }

    // So, we have no next threads in the queue to notify about
    // lock releasing event. Let's just put `0` to the lock, will
    // delete ourself from the queue and exit.
}
```

这就是所有有关`队列自旋锁`的理论，下面我们将探究在Linux内核中这个机制是如何实现的。`队列自旋锁`的实现比上面的伪代码更加复杂和混乱，但是用心学习会引导成功。

## 2 队列自旋锁的类型定义

现在我们了解了一些`队列自旋锁`的理论知识，是时候了解这一机制在Linux内核中的实现了。在[include/asm-generic/qspinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/qspinlock.h#L109)中提供了获取、释放自旋锁的API，如下：

```C
#define arch_spin_is_locked(l)		queued_spin_is_locked(l)
#define arch_spin_is_contended(l)	queued_spin_is_contended(l)
#define arch_spin_value_unlocked(l)	queued_spin_value_unlocked(l)
#define arch_spin_lock(l)		queued_spin_lock(l)
#define arch_spin_trylock(l)		queued_spin_trylock(l)
#define arch_spin_unlock(l)		queued_spin_unlock(l)
```

所有这些宏扩展了同一头文件下的函数的调用。此外，Linux内核队列自旋锁的结构用`qspinlock`结构表示，在[include/asm-generic/qspinlock_types.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/qspinlock_types.h#L22)头文件中定义，如下：

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

`qspinlock`结构中`val`字段表示自旋锁的状态。这个`4`字节的字段可以表示为：

* `locked` -- 锁定标识;
* `pending` -- 未决位;
* `locked_pending` -- `MCS`锁数组的`per_cpu`索引；
* `tail` -- 队列尾部的处理器数量。

在我们分析`队列自旋锁`的`API`之前，`qspinlock`结构中的`val`字段是`atomic_t`类型，它代表原子变量，也就是`一次一个操作`的变量。因此，所有这个字段的操作都是[原子的](https://en.wikipedia.org/wiki/Linearizability)。例如，读取`val`的值的API：

```C
static __always_inline int queued_spin_is_locked(struct qspinlock *lock)
{
	return atomic_read(&lock->val);
}
```

## 3 队列自旋锁的加锁实现过程

现在我们已经了解了Linux内核中表示队列自旋锁数据结构，那么是时候看看`队列自旋锁`API的实现，首先我们来看`arch_spin_lock`这个主要函数，从函数名我们可以理解，它允许线程获取锁。如下：

```C
#define arch_spin_lock(l)               queued_spin_lock(l)
```

`queued_spin_lock`函数在[include/asm-generic/qspinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/qspinlock.h#L74)头文件实现，如下：

```C
static __always_inline void queued_spin_lock(struct qspinlock *lock)
{
	u32 val = 0;

	if (likely(atomic_try_cmpxchg_acquire(&lock->val, &val, _Q_LOCKED_VAL)))
		return;

	queued_spin_lock_slowpath(lock, val);
}
```

这个函数看起来很简单，这个函数只需要一个参数，即：`qspinlock`，即将被锁定。

### 3.1 无竞争情形下的处理过程

让我们考虑`队列`锁为空，现在第一个线程想要获取锁的情况。`queued_spin_lock`函数从调用`atomic_try_cmpxchg_acquire`宏开始，通过宏的名称我们可以猜到，它尝试执行原子的`CMPXCHG`指令。`atomic_try_cmpxchg_acquire`宏在[include/linux/atomic-fallback.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/atomic-fallback.h#L926)中定义，如下：

```C
static inline bool
atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg_acquire(v, o, new);
	if (unlikely(r != o))
		*old = r;
	return likely(r == o);
}
```

`atomic_cmpxchg_acquire`宏在[include/linux/atomic-fallback.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/atomic-fallback.h#L865)头文件中定义，扩展为`atomic_cmpxchg`宏：

```C
#define atomic_cmpxchg_acquire atomic_cmpxchg
```

`atomic_cmpxchg`基于CPU架构实现，在`x86_64`架构下最终会展开为`arch_cmpxchg`的宏，在[arch/x86/include/asm/cmpxchg.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/cmpxchg.h#L148)头文件中定义，如下：

```C
#define __cmpxchg(ptr, old, new, size)					\
	__raw_cmpxchg((ptr), (old), (new), (size), LOCK_PREFIX)

#define arch_cmpxchg(ptr, old, new)					\
	__cmpxchg(ptr, old, new, sizeof(*(ptr)))
```

`arch_cmpxchg`宏使用几乎相同的参数集合扩展了`__cmpxchg`宏，添加了`size`参数；`__cmpxchg`宏扩展了`__raw_cmpxchg`宏，添加了`LOCK_PREFIX`参数。`__raw_cmpxchg`最终执行如下：

```C
#define __raw_cmpxchg(ptr, old, new, size, lock)			\
({									\
	__typeof__(*(ptr)) __ret;					\
	__typeof__(*(ptr)) __old = (old);				\
	__typeof__(*(ptr)) __new = (new);				\
	switch (size) {							\
	...
	...
	case __X86_CASE_L:						\
	{								\
		volatile u32 *__ptr = (volatile u32 *)(ptr);		\
		asm volatile(lock "cmpxchgl %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}	
	...
	...
	...
	__ret;								\
})
```

`__raw_cmpxchg`的主要功能是将`old`的值和`ptr`指向的值进行比较，如果相同，将`new`保存到`ptr`指向的地址，并返回`ptr`中初始值。

现在返回到`atomic_try_cmpxchg_acquire`函数，在`atomic_cmpxchg_acquire`宏执行后，该宏返回内存地址之前的值。现在只有一个线程尝试获取锁，因此`atomic_try_cmpxchg_acquire`返回`true`，`queued_spin_lock`函数直接返回：

```C
if (likely(atomic_try_cmpxchg_acquire(&lock->val, &val, _Q_LOCKED_VAL)))
	return;
```

### 3.2 竞争情形的处理过程

到目前为止，我们只有一个线程持有锁的无竞争的情况（即快速路径）。现在让我们来考虑竞争情况（即慢路径），假设第一个线程已经获取了锁然后第二个线程尝试获取相同的锁。第二个线程将从同样的`queued_spin_lock`函数开始，因为第一个线程已经持有了锁，因此，`queued_spin_lock_slowpath`函数将会被调用。`queued_spin_lock_slowpath`函数在[kernel/locking/qspinlock.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/qspinlock.c#L314)源码文件中实现，如下：

```C
void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	...
	if (pv_enabled())
		goto pv_queue;

	if (virt_spin_lock(lock))
		return;

	...
	...
	...
}
```

`pv_enabled`检查`pvqspinlock`的状态。`pvqspinlock`是在[准虚拟化（paravirtualized）](https://en.wikipedia.org/wiki/Paravirtualization)环境中的`队列自旋锁`。由于我们只关注Linux内核同步原语，我们跳过这些不直接相关部分。

#### 3.2.1 不需要排队的情况

接下来，如果当前锁包含挂起位（即，`val == _Q_PENDING_VAL`）时，表示当前线程想要获取锁，但锁被其他的线程获取，同时队列为空。在这种情况下，我们获取有限次数的锁状态。这样做是为了优化，避免因`mcs_spinlock`数组缓存失效引起的延时，而这种延时是不必要的。如下：

```C
	if (val == _Q_PENDING_VAL) {
		int cnt = _Q_PENDING_LOOPS;
		val = atomic_cond_read_relaxed(&lock->val,
					       (VAL != _Q_PENDING_VAL) || !cnt--);
	}
```

接下来，我们检查锁的竞争状态，如果处于竞争状态（即：`val & ~_Q_LOCKED_MASK`）时，此时除了排队外，别无选择。因此，跳转到`queue`标签进行排队;

```C
	if (val & ~_Q_LOCKED_MASK)
		goto queue;
```

否则，我们设置锁的挂起位，表示我们已经获取到锁;

```C
	val = queued_fetch_set_pending_acquire(lock);
```

同样，如果我们观察到竞争，撤消挂起位后进入排队；

```C
	if (unlikely(val & ~_Q_LOCKED_MASK)) {
		if (!(val & _Q_PENDING_MASK))
			clear_pending(lock);

		goto queue;
	}
```

在此之后，在等待锁的所有者释放后，我们允许拿走锁，我们清除锁的挂起位并设置锁定位。现在，我们已经获取到锁，从`queued_spin_lock_slowpath`函数返回。如下：

```C
	if (val & _Q_LOCKED_MASK)
		atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_MASK));

	clear_pending_set_locked(lock);
	lockevent_inc(lock_pending);
	return;
```

#### 3.2.2 需要排队的情况

* MCS锁介绍

在深入排队之前，我们将首先了解`MCS`锁的机制。我们已经知道，系统中的每个处理器都有自己的锁副本。锁使用`mcs_spinlock`结构表示，在[kernel/locking/mcs_spinlock.h](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/mcs_spinlock.h#L18)中定义，如下：

```C
struct mcs_spinlock {
	struct mcs_spinlock *next;
	int locked; /* 1 if lock acquired */
	int count;  /* nesting count, see qspinlock.c */
};
```

第一个字段`next`表示队列中指向下一个线程的指针；`locked`表示当前线程在队列中的状态，`1`表示已经获取到锁，`0`表示未获取到锁；`count`字段表示嵌套锁。要了解嵌套锁是什么，现在想象下面这个场景，一个线程获取到锁，现在发生了硬件中断，中断处理程序也尝试获取锁。对于这种情况，每个处理器不仅具有`mcs_spinlock`的副本，也包括这些结构的数组：

```C
#define MAX_NODES	4
...
struct qnode {
	struct mcs_spinlock mcs;
#ifdef CONFIG_PARAVIRT_SPINLOCKS
	long reserved[2];
#endif
};
...
static DEFINE_PER_CPU_ALIGNED(struct qnode, qnodes[MAX_NODES]);
```

该数组允许在下面四个事件上下文中四次尝试获取锁，包括：正常任务上下文、 硬件中断上下文、软件中断上下文、不可屏蔽的中断上下文。

* 排队状态

注意我们还没创建`队列`。这里我们不需要，因为对于两个线程来说，它只会导致不必要的内存访问延时。在其他的情况下，第一个线程可能在这个时候释放其锁。我们只有在`lock->val`包含`_Q_LOCKED_VAL | _Q_PENDING_VAL`的情况下，我们才开始建立`队列`。开始建立`队列`时，我们需要获取执行线程的处理器中`qnodes`的副本，计算队列的尾部和索引，如下：

```C
pv_queue:
	node = this_cpu_ptr(&qnodes[0].mcs);
	idx = node->count++;
	tail = encode_tail(smp_processor_id(), idx);
	...
	node = grab_mcs_node(node, idx);
```

在此之后，我们设置`locked`为0，因为这个线程还没有获取到锁，`next`为`NULL`，因为我们不清楚队列中的其他条目。如下：

```C
	node->locked = 0;
	node->next = NULL;
```

我们已经为执行当前线程想获取锁的处理器创建了队列的`per-cpu`拷贝，这意味着锁的拥有者可能在这之前释放了锁。因此我们通过`queued_spin_trylock`函数的调用尝试去再次获取锁。

```C
	if (queued_spin_trylock(lock))
		goto release;
```

`queued_spin_trylock`函数在[include/asm-generic/qspinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/qspinlock.h#L58)头文件中定义，函数功能同`queued_spin_lock`函数几乎相同：

```C
static __always_inline int queued_spin_trylock(struct qspinlock *lock)
{
	u32 val = atomic_read(&lock->val);
	if (unlikely(val))
		return 0;
	return likely(atomic_try_cmpxchg_acquire(&lock->val, &val, _Q_LOCKED_VAL));
}
```

如果`queued_spin_trylock`成功获取到锁，那么我们跳过`释放`标签而释放`队列`中的一个节点；如果不成功，我们更新队列的尾部：

```C
	old = xchg_tail(lock, tail);
	next = NULL;
```

下一步是检查`队列`是否为空。在这种情况下，我们需要将以前的条目和新的条目链接起来。在等钱MSC锁时，下一个指针可能被另一个等待锁的线程设置，我们乐观的加载下一个指针并预先获取缓存进行写入，以减少即将到来的MCS解锁操作中的延迟，如果添加了新的节点，我们使用[PREFETCHW](http://www.felixcloutier.com/x86/PREFETCHW.html)指令从下一个队列条目指向的内存中预先取出缓存线（cache line）。如下：

```C
	if (old & _Q_TAIL_MASK) {
		prev = decode_tail(old);
		WRITE_ONCE(prev->next, node);

		pv_wait_node(node, prev);
		arch_mcs_spin_lock_contended(&node->locked);

		next = READ_ONCE(node->next);
		if (next)
			prefetchw(next);
	}
}
```

现在我们成为了队列的头部，这意味着即将有`MCS`进行解锁操作并且下一个实体会被创建。但是在我们能够获取锁之前，我们需要至少等待两个事件：当前锁的拥有者释放锁和第二个线程处于`待定`位也获取锁。

```C
	val = atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_PENDING_MASK));
```

在这个两个线程都释放锁后，`队列`的头部会持有锁，进入锁定状态。

* 锁定状态

在此阶段，我们只是需要更新`队列`尾部然后移除从队列中移除头部。如下：

```C
locked:
	if ((val & _Q_TAIL_MASK) == tail) {
		if (atomic_try_cmpxchg_relaxed(&lock->val, &val, _Q_LOCKED_VAL))
			goto release; /* No contention */
	}
	set_locked(lock);

	if (!next)
		next = smp_cond_load_relaxed(&node->next, (VAL));

	arch_mcs_spin_unlock_contended(&next->locked);
	pv_kick_node(lock, next);
```

* 释放节点

减少MCS锁的引用计数来释放节点。如下：

```C
release:
	__this_cpu_dec(qnodes[0].mcs.count);
```

至此，我们已经完成了队列自旋锁加锁过程的介绍。

## 4 队列自旋锁的解锁实现过程

同`arch_spin_lock`一起，`arch_spin_unlock`宏定义如下：

```C
#define arch_spin_unlock(l)		queued_spin_unlock(l)
```

`queued_spin_unlock`函数在[include/asm-generic/qspinlock.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/qspinlock.h#L89)中实现，如下：

```C
static __always_inline void queued_spin_unlock(struct qspinlock *lock)
{
	smp_store_release(&lock->locked, 0);
}
```

`smp_store_release`宏扩展为`__smp_store_release`宏，在`x86_64`架构下最终扩展如下：

```C
#define __smp_store_release(p, v)					\
do {									\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	WRITE_ONCE(*p, v);						\
} while (0)
```

可以看到，`queued_spin_unlock`函数将`lock->locked`变量置为`0`即完成了解锁过程。

## 5 结束语

在上一部分我们已经见到了Linux内核提供的第一个同步原语 -- `自旋锁`，在这个部分我们分析了`队列自旋锁`的实现机制。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
