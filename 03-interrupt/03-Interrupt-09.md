# 中断和中断处理 （第九部分）

## 0 介绍

在上一部分中，我们详细分析了`init_IRQ`实现过程。接下来的这一节我们将继续深入分析外部硬件中断的剩余部分。

中断处理会有一些特点，其中最主要的两个是：

* 中断处理必须快速执行完毕
* 有时中断处理必须做很多冗长的事情

就像你所想到的，我们几乎不可能同时做到这两点。正因为如此，之前的中断被分为两部分：`前半部`和`后半部`。`后半部`曾经是Linux内核延后中断执行的一种方式，现在它作为一个术语代表内核中所有延后中断的机制。中断延时处理时，中断的某些操作可能会推迟到负载少的时候执行。如你所知，中断处理程序运行于中断处理上下文中，此时禁止响应后续的中断，所以要避免中断处理代码长时间执行。但有些中断却又需要执行很多工作，所以中断处理有时会被分为两部分。第一部分中，中断处理先只做尽量少的重要工作，接下来提交第二部分给内核调度，然后就结束运行。当系统比较空闲并且处理器上下文允许处理中断时，第二部分被延后的剩余任务就会开始执行。

Linux内核中有三种实现延后中断的方式，包括：

* `软中断`
* `tasklets`
* `工作队列`

在本文我们将详细介绍这三种实现方式。

## 1 软中断

伴随着内核对并行处理的支持，出于性能考虑，所有新的下半部实现方案都基于被称之为 `ksoftirqd`(稍后将详细讨论)的内核线程。每个处理器都有自己的内核线程，名字叫做 `ksoftirqd/n`，n是处理器的编号。我们可以通过系统命令 `systemd-cgls` 看到它们：

```bash
$ systemd-cgls -k | grep ksoft
├─   3 [ksoftirqd/0]
├─  13 [ksoftirqd/1]
├─  18 [ksoftirqd/2]
├─  23 [ksoftirqd/3]
├─  28 [ksoftirqd/4]
├─  33 [ksoftirqd/5]
├─  38 [ksoftirqd/6]
├─  43 [ksoftirqd/7]
```

由`spawn_ksoftirqd`函数启动这些线程，这个函数在[kernel/softirq.c](https://github.com/torvalds/linux/blob/v5.4/kernel/softirq.c#L680)文件中实现，通过早期[initcall](http://www.compsoc.man.ac.uk/~moz/kernelnewbies/documents/initcall/index.html)被调用，如下：

```C
early_initcall(spawn_ksoftirqd);
```

### 1.1 软中断初始化

软中断在Linux内核编译时就静态确定了。`open_softirq`函数负责`softirq`初始化，[kernel/softirq.c](https://github.com/torvalds/linux/blob/v5.4/kernel/softirq.c#L455)中实现，如下：

```C
void open_softirq(int nr, void (*action)(struct softirq_action *))
{
	softirq_vec[nr].action = action;
}
```

这个函数有两个参数：

* `nr` -- `softirq_vec`数组的索引序号;
* `action` -- 软中断处理的函数指针

`softirq_vec`数组在同一个源文件中定义，如下：

```C
static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;
```

`softirq_vec`数组包含了`NR_SOFTIRQS`(其值为10)个不同`softirq`类型的`softirq_action`。目前Linux内核定义了十种软中断向量，其中两个tasklet相关，两个网络相关，两个块处理相关，两个定时器相关，一个调度器相关，一个RCU相关。所有这些类型在[include/linux/interrupt.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/interrupt.h#L513)中定义，如下：

```C
enum
{
	HI_SOFTIRQ=0,
	TIMER_SOFTIRQ,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	BLOCK_SOFTIRQ,
	IRQ_POLL_SOFTIRQ,
	TASKLET_SOFTIRQ,
	SCHED_SOFTIRQ,
	HRTIMER_SOFTIRQ, /* Unused, but kept as tools rely on the numbering. Sigh! */
	RCU_SOFTIRQ,    /* Preferable RCU should always be the last softirq */
	NR_SOFTIRQS
};
```

以上软中断的名字在下面的数组中定义：

```C
const char * const softirq_to_name[NR_SOFTIRQS] = {
	"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL",
	"TASKLET", "SCHED", "HRTIMER", "RCU"
};
```

我们可以通过`/proc/softirqs`输出中看到相关内容，如下：

```bash
~$ cat /proc/softirqs
                    CPU0       CPU1       CPU2       CPU3       
          HI:          0          0          0          0
       TIMER:      47852      46221      45582      43560
      NET_TX:          2          1          0          1
      NET_RX:        108       4811       7109         86
       BLOCK:        800        855       2410       2180
    IRQ_POLL:          0          0          0          0
     TASKLET:          1          1          5          0
       SCHED:      15624      17410      18346      16795
     HRTIMER:          0          0          0          0
         RCU:      49561      50028      52453      44541
```

`softirq_vec`数组的类型为`softirq_action`，这是软中断机制里一个重要的数据结构。`softirq_action`结构只包含一个指向中断处理函数的成员，如下：

```C
struct softirq_action
{
	void	(*action)(struct softirq_action *);
};
```

### 1.2 软中断调度过程

`open_softirq`函数实际上用`softirq_action`参数填充了`softirq_vec`数组。由`open_softirq`注册的延后中断处理函数由 `raise_softirq`调用。这个函数只有一个参数 -- 软中断序号`nr`。来看下它的实现：

```C
void raise_softirq(unsigned int nr)
{
	unsigned long flags;

	local_irq_save(flags);
	raise_softirq_irqoff(nr);
	local_irq_restore(flags);
}
```

可以看到在`local_irq_save`和`local_irq_restore`两个宏之间调用了`raise_softirq_irqoff`函数。`local_irq_save`和`local_irq_restore`宏在[include/linux/irqflags.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irqflags.h#L146)头文件中实现。`local_irq_save`宏保存[eflags](https://en.wikipedia.org/wiki/FLAGS_register)寄存器中的[IF](https://en.wikipedia.org/wiki/Interrupt_flag)标志位并且禁用了当前处理器的中断；`local_irq_restore`宏进行完全相反的操作，装回之前保存的中断标志位然后允许中断。这里之所以要禁用中断是因为将要运行的 `softirq`中断处理运行于中断上下文中。

`raise_softirq_irqoff`函数在同一个文件中实现，如下：

```C
inline void raise_softirq_irqoff(unsigned int nr)
{
	__raise_softirq_irqoff(nr);

	if (!in_interrupt())
		wakeup_softirqd();
}
```

首先，通过设置当前处理器上软中断标志位(`local_softirq_pending`)中和`nr`对应的掩码位来标记软中断是否延时。然后，通过`in_interrupt`函数获得`irq_count`值，通过该值来检测cpu是否处于中断环境。如果处于中断上下文就退出该函数；否则，调用`wakeup_softirqd`函数激活当前处理器上的`ksoftirqd`内核线程。如下：

```C
static void wakeup_softirqd(void)
{
	struct task_struct *tsk = __this_cpu_read(ksoftirqd);

    if (tsk && tsk->state != TASK_RUNNING)
        wake_up_process(tsk);
}
```

每个`ksoftirqd`内核线程都运行`run_ksoftirqd`函数来检测是否有延后中断需要处理，如果有的话就会调用`__do_softirq`函数。`__do_softirq`读取当前处理器对应的`local_softirq_pending`软中断标记，并调用所有已被标记中断对应的处理函数。在执行延后函数期间，可能会发生新的软中断，这会导致用户态代码由于`__do_softirq`要处理很多延后中断而很长时间不能返回。为了解决这个问题，系统限制了延后中断处理的最大耗时，如下：

```C
asmlinkage __visible void __softirq_entry __do_softirq(void)
{
    unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
    ...
    ...
    ...
    restart:
    while ((softirq_bit = ffs(pending))) {
        ...
        h->action(h);
        ...
    }
    ...
    ...
    ...
    pending = local_softirq_pending();
    if (pending) {
        if (time_before(jiffies, end) && !need_resched() &&
            --max_restart)
                goto restart;
    }
    ...
}
```

除周期性检测是否有延后中断需要执行之外，系统还会在一些关键时间点上检测。一个主要的检测时间点在`do_IRQ`函数被调用时，这是 Linux内核中执行延后中断的主要时机。在`do_IRQ`函数将要完成中断处理时它会调用[arch/x86/include/asm/apic.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/apic.h#L534)中定义的`exiting_irq`函数，`exiting_irq`调用`irq_exit`函数。`irq_exit`函数会检测当前处理器上下文是否有延后中断，有的话就会调用`invoke_softirq`，如下：

```C
void irq_exit(void)
{
    ...
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();
    ...
}
```

这样就调用到了我们上面提到的`__do_softirq`函数。每个`softirq`都有如下的阶段：

* 通过`open_softirq`函数注册一个软中断；
* 通过`raise_softirq`函数标记一个软中断来激活它；
* 在此之后，所有被标记的软中断将会在Linux内核下一次执行周期性软中断检测时得以调度；
* 对应此类型软中断的处理函数也就得以执行。

从上述可看出，软中断是静态分配的，这对于后期加载的内核模块将是一个问题。基于软中断实现的`tasklets`解决了这个问题。

## 2 Tasklets

如果你阅读Linux内核源码中软中断相关的代码，你会发现它很少会被用到。内核中实现延后中断的主要途径是`tasklets`。正如上面说的，`tasklets`建立在`softirq`中断上，它是基于`TASKLET_SOFTIRQ`和`HI_SOFTIRQ`两个软中断实现的。

简而言之，`tasklets`是运行时分配和初始化的软中断。和软中断不同的是，同一类型的`tasklets`不能同时运行在多个处理器上。我们已经了解到一些关于软中断的知识，当然上面的文字并不能详细讲解所有的细节，但我们现在可以通过直接阅读代码一步步的更深入了解Tasklets。

### 2.1 Tasklets初始化

Tasklets在`softirq_init`函数实现，该函数在[kernel/softirq.c](https://github.com/torvalds/linux/blob/v5.4/kernel/softirq.c#L575)中定义如下：

```C
void __init softirq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		per_cpu(tasklet_vec, cpu).tail =
			&per_cpu(tasklet_vec, cpu).head;
		per_cpu(tasklet_hi_vec, cpu).tail =
			&per_cpu(tasklet_hi_vec, cpu).head;
	}

	open_softirq(TASKLET_SOFTIRQ, tasklet_action);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action);
}
```

可以通过`for_each_possible_cpu`宏来获得系统中所有的处理器，`possible_cpu`是系统运行期间插入的处理器集合，所有的可用的处理器存储在`cpu_possible_mask`位图中，你可以在[kernel/cpu.c](https://github.com/torvalds/linux/blob/v5.4/kernel/cpu.c#L2291)中找到其定义，如下：

```C
typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;
...
...
#ifdef CONFIG_INIT_ALL_POSSIBLE
struct cpumask __cpu_possible_mask __read_mostly
	= {CPU_BITS_ALL};
#else
struct cpumask __cpu_possible_mask __read_mostly;
#endif
```

通过`for_each_possible_cpu`宏遍历所有处理器，每个处理器初始化两个`per-cpu`变量，`tasklet_vec`和`tasklet_hi_vec`。这两个`per-cpu`变量和 `softirq_init`函数都在[kernel/softirq.c](https://github.com/torvalds/linux/blob/v5.4/kernel/softirq.c#L468)中定义，如下：

```C
static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec);
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec);
```

`tasklet_head`结构代表一组`Tasklets`，它包含两个成员：`head`和`tail`。如下：

```C
struct tasklet_head {
	struct tasklet_struct *head;
	struct tasklet_struct **tail;
};
```

`tasklet_struct`结构代表一个`Tasklet`，在[include/linux/interrupt.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/interrupt.h#L592)中定义，如下：

```C
struct tasklet_struct
{
	struct tasklet_struct *next;
	unsigned long state;
	atomic_t count;
	void (*func)(unsigned long);
	unsigned long data;
};
```

该数据结构字段说明如下：

* `next` -- 调度队列中的下一个`Tasklet`；
* `state` -- `Tasklet`状态；
* `count` -- `Tasklet`是否处于活动状态；
* `func` -- `Tasklet`的回调函数；
* `data` -- 回调函数的参数；

在`softirq_init`函数中初始化了两个`tasklets`数组：`tasklet_vec`和`tasklet_hi_vec`，即：Tasklets 和高优先级Tasklets。在 `softirq_init`函数的最后两次调用了`open_softirq`：

```C
open_softirq(TASKLET_SOFTIRQ, tasklet_action);
open_softirq(HI_SOFTIRQ, tasklet_hi_action);
```

### 2.2 Tasklets调度过程

`open_softirq`函数的主要作用是初始化软中断，接下来让我们看看其实现过程。和Tasklets相关的软中断处理函数有两个，分别是`tasklet_action`和`tasklet_hi_action`。其中`tasklet_action`和`TASKLET_SOFTIRQ`关联， `tasklet_hi_action`和`HI_SOFTIRQ`关联。

Linux内核提供一些操作Tasklets的API。首先是`tasklet_init`函数，它接受一个`task_struct`数据结构，一个处理函数，和另外一个参数，并利用这些参数来初始化所给的`task_struct`结构，如下：

```C
void tasklet_init(struct tasklet_struct *t,
                  void (*func)(unsigned long), unsigned long data)
{
    t->next = NULL;
    t->state = 0;
    atomic_set(&t->count, 0);
    t->func = func;
    t->data = data;
}
```

另外在[include/linux/interrupt.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/interrupt.h#L601)有两个宏可以静态地初始化一个tasklet，如下：

```C
#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }

#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }
```

Linux内核提供下面两个函数标记一个tasklet已经准备就绪，如下：

```C
void tasklet_schedule(struct tasklet_struct *t);
void tasklet_hi_schedule(struct tasklet_struct *t);
```

第一个函数使用普通优先级调度一个tasklet，第二个使用高优先级，这两个函数的实现都类似。以`tasklet_schedule`的实现为例，如下：

```C
static inline void tasklet_schedule(struct tasklet_struct *t)
{
	if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
		__tasklet_schedule(t);
}

void __tasklet_schedule(struct tasklet_struct *t)
{
	__tasklet_schedule_common(t, &tasklet_vec,
				  TASKLET_SOFTIRQ);
}

static void __tasklet_schedule_common(struct tasklet_struct *t,
				      struct tasklet_head __percpu *headp,
				      unsigned int softirq_nr)
{
	struct tasklet_head *head;
	unsigned long flags;

	local_irq_save(flags);
	head = this_cpu_ptr(headp);
	t->next = NULL;
	*head->tail = t;
	head->tail = &(t->next);
	raise_softirq_irqoff(softirq_nr);
	local_irq_restore(flags);
}
```

我们看到它检测并设置所给的`tasklet`为`TASKLET_STATE_SCHED`状态，然后调用`__tasklet_schedule`函数。`__tasklet_schedule`调用`__tasklet_schedule_common`函数，传递`tasklet_vec`和`TASKLET_SOFTIRQ`参数。`__tasklet_schedule_common`函数首先保存中断标志(`flags`)并禁用中断，继而将新的`tasklet`添加到`struct tasklet_head`(即，`tasklet_vec`)的尾部，然后调用`raise_softirq_irqoff`函数(索引为`TASKLET_SOFTIRQ`)激活软中断，最后启用中断并恢复保存的中断标记。

当Linux内核调度器决定去运行一个延后函数时，`tasklet_action`函数作为和`TASKLET_SOFTIRQ`相关联的延后函数被调用。同样的，`tasklet_hi_action`作为和`HI_SOFTIRQ`相关联的延后函数被调用。接下来，我们来看下`tasklet_action`函数的实现，在[kernel/softirq.c](https://github.com/torvalds/linux/blob/v5.4/kernel/softirq.c#L539)中实现，如下：

```C
static __latent_entropy void tasklet_action(struct softirq_action *a)
{
	tasklet_action_common(a, this_cpu_ptr(&tasklet_vec), TASKLET_SOFTIRQ);
}

static void tasklet_action_common(struct softirq_action *a,
				  struct tasklet_head *tl_head,
				  unsigned int softirq_nr)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = tl_head->head;
	tl_head->head = NULL;
	tl_head->tail = &tl_head->head;
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;
		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED,
							&t->state))
					BUG();
				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = NULL;
		*tl_head->tail = t;
		tl_head->tail = &t->next;
		__raise_softirq_irqoff(softirq_nr);
		local_irq_enable();
    }
}
```

`tasklet_action_common`函数开始时利用`local_irq_disable`宏禁用了当前处理器的中断；接下来获取到当前处理器对应的tasklet列表并把它设置为`NULL`，这是因为所有的tasklet都将被执行；然后使能当前处理器的中断。循环遍历tasklet列表，每一次遍历都会对当前tasklet调用`tasklet_trylock`函数来更新它的状态为`TASKLET_STATE_RUN`，如下

```C
static inline int tasklet_trylock(struct tasklet_struct *t)
{
    return !test_and_set_bit(TASKLET_STATE_RUN, &(t)->state);
}
```

如果这个操作成功了就会执行此tasklet的处理函数(在`tasklet_init`中所设置的)，然后调用`tasklet_unlock`函数清除他的`TASKLET_STATE_RUN`状态。如果`tasklet_trylock`失败，将当前执行的tasklet放到tasklet列表的尾部，启用下次中断继续执行。

## 3 工作队列

`工作队列`是另外一个处理延后函数的概念，主要用于内核驱动，它大体上和`tasklets`类似，也有些不同。工作队列运行于内核进程上下文，而`tasklets`运行于软中断上下文。这意味着`工作队列`函数不必像`tasklets`一样必须是原子性的。Tasklets总是运行于它提交的那个处理器，工作队列在默认情况下使用同样的方式。

### 3.1 工作队列初始化

工作队列中涉及到几个不同的概念，之间容易混淆，主要包括：

* work -- 工作；
* workqueue -- 工作队列，一个workqueue中包含多个work；
* worker -- 工人，每个worker对应一个`work_thread()`内核线程；
* worker_pool -- 工人集合；
* pwq(pool_workqueue) -- 中介，负责建立起workqueue和worker_pool之间的关系。一个workqueue包含多个pwq，pwq和worker_pool之间一一对应。

#### 3.1.1 工作(work)

工作队列内的工作，使用`work_struct`来表示，在[include/linux/workqueue.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/workqueue.h#L102)中定义，如下：

```C
struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
#ifdef CONFIG_LOCKDEP
	struct lockdep_map lockdep_map;
#endif
};
```

这个结构中我们需要关注两个字段：`func` -- 工作的执行的函数，`data` -- 这个函数的参数。

Linux内核提供了如下宏静态创建一个工作，它需要两个参数：工作队列的名称和工作队列函数，如下：

```C
#define DECLARE_WORK(n, f) \
    struct work_struct n = __WORK_INITIALIZER(n, f)
```

我们还可以在运行时动态创建，如下：

```C
#define INIT_WORK(_work, _func)						\
	__INIT_WORK((_work), (_func), 0)

#define __INIT_WORK(_work, _func, _onstack)				\
	do {								\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		INIT_LIST_HEAD(&(_work)->entry);			\
		(_work)->func = (_func);				\
	} while (0)
```

`INIT_WORK`宏使用`struct work_struct`结构(`_work`)和在这个工作里调度运行的函数(`_func`)来创建工作。

#### 3.1.2 工人集合(worker_pool)

每个执行work的线程叫做worker，一组worker的集合叫做work_pool。在Linux内核中使用`worker_pool`结构来表示，在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L147)中定义，如下：

```C
struct worker_pool {
	spinlock_t		lock;		/* the pool lock */
	int			cpu;		/* I: the associated cpu */
	int			node;		/* I: the associated node ID */
	int			id;		/* I: pool ID */
	unsigned int		flags;		/* X: flags */

	unsigned long		watchdog_ts;	/* L: watchdog timestamp */

	struct list_head	worklist;	/* L: list of pending works */

	int			nr_workers;	/* L: total number of workers */
	int			nr_idle;	/* L: currently idle workers */
    ...
    ...
    ...
} ____cacheline_aligned_in_smp;
```

因为这个结构有比较多的成员，这里就不一一列举，下面只讨论上面列出的这几个。`worker_pool`分成两类，正常的工人集合(normal worker_pool)和未绑定的工人集合(unbound worker_pool)。

正常的工人集合(normal worker_pool)在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L5866)文件中的`workqueue_init_early`函数实现对`worker_pool`的初始化。如下：

```C
int __init workqueue_init_early(void)
{
	int std_nice[NR_STD_WORKER_POOLS] = { 0, HIGHPRI_NICE_LEVEL };
    ...
    ...
	for_each_possible_cpu(cpu) {
		struct worker_pool *pool;
		i = 0;
		for_each_cpu_worker_pool(pool, cpu) {
			BUG_ON(init_worker_pool(pool));
			pool->cpu = cpu;
			cpumask_copy(pool->attrs->cpumask, cpumask_of(cpu));
			pool->attrs->nice = std_nice[i++];
			pool->node = cpu_to_node(cpu);

			/* alloc pool ID */
			mutex_lock(&wq_pool_mutex);
			BUG_ON(worker_pool_assign_id(pool));
			mutex_unlock(&wq_pool_mutex);
		}
	}
    ...
    ...
}
...
...
static DEFINE_PER_CPU_SHARED_ALIGNED(struct worker_pool [NR_STD_WORKER_POOLS], cpu_worker_pools);
```

可以看到，`cpu_worker_pools`是个percpu变量，包括两个worker_pool。一个是正常优先级(nice=0)，一个是高优先级(nice=HIGHPRI_NICE_LEVEL)。针对每个`worker_pool`都调用`init_worker_pool`函数进行初始化。

未绑定的工人集合(unbound worker_pool)在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L333)中定义，如下：

```C
static DEFINE_HASHTABLE(unbound_pool_hash, UNBOUND_POOL_HASH_ORDER);
```

#### 3.1.3 工作队列(workqueue)

工作队列(workqueue)指工作(work)的集合。一个工作队列中包含多个工作。工作队列在Linux内核中使用`struct workqueue_struct`结构表示，在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L238)中定义，如下：

```C
struct workqueue_struct {
	struct list_head	pwqs;		/* WR: all pwqs of this wq */
	struct list_head	list;		/* PR: list of all workqueues */
    ...
};
```

在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L5866)文件中的`workqueue_init_early`函数实现对`workqueue`的初始化。如下：

```C
int __init workqueue_init_early(void)
{
    ...
    ...
	system_wq = alloc_workqueue("events", 0, 0);
	system_highpri_wq = alloc_workqueue("events_highpri", WQ_HIGHPRI, 0);
	system_long_wq = alloc_workqueue("events_long", 0, 0);
	system_unbound_wq = alloc_workqueue("events_unbound", WQ_UNBOUND,
					    WQ_UNBOUND_MAX_ACTIVE);
	system_freezable_wq = alloc_workqueue("events_freezable",
					      WQ_FREEZABLE, 0);
	system_power_efficient_wq = alloc_workqueue("events_power_efficient",
					      WQ_POWER_EFFICIENT, 0);
	system_freezable_power_efficient_wq = alloc_workqueue("events_freezable_power_efficient",
					      WQ_FREEZABLE | WQ_POWER_EFFICIENT,
					      0);
	BUG_ON(!system_wq || !system_highpri_wq || !system_long_wq ||
	       !system_unbound_wq || !system_freezable_wq ||
	       !system_power_efficient_wq ||
	       !system_freezable_power_efficient_wq);
}
```

可以看到，通过`alloc_workqueue`函数创建了`system_wq`, `system_highpri_wq`, `system_long_wq`, `system_unbound_wq` 等7个workqueue。

#### 3.1.4 工人(worker)

Linux内核提供了特殊的per-CPU线程，称之为`kworker`，这些线程获取可执行的work后执行。这些线程在`init`进程初始化过程中，调用`workqueue_init`函数创建的。`workqueue_init`函数在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L5946)中实现，如下：

```C
int __init workqueue_init(void)
{
    ...
    ...
	for_each_online_cpu(cpu) {
		for_each_cpu_worker_pool(pool, cpu) {
			pool->flags &= ~POOL_DISASSOCIATED;
			BUG_ON(!create_worker(pool));
		}
	}

	hash_for_each(unbound_pool_hash, bkt, pool, hash_node)
		BUG_ON(!create_worker(pool));
    ...
}
```

`create_worker`函数创建`worker`线程，执行`worker_thread`函数，如下：

```C
static struct worker *create_worker(struct worker_pool *pool)
{
    ...
    ...
    	worker->task = kthread_create_on_node(worker_thread, worker, pool->node,
					      "kworker/%s", id_buf);
    ...
    ...
}
```

我们可以通过下面的方式来查看所有的worker：

```bash
systemd-cgls -k | grep kworker
├─   5 [kworker/0:0-events]
├─   6 [kworker/0:0H-kblockd]
├─   7 [kworker/u8:0-events_unbound]
├─  13 [kworker/0:1-events]
├─  19 [kworker/1:0-events]
├─  20 [kworker/1:0H-kblockd]
├─  25 [kworker/2:0-events]
├─  26 [kworker/2:0H]
...
```

#### 3.1.5 中介(pwq，pool_workqueue)

`pool_workqueue`结构用来建立`worker_pool`和`workqueue_struct`之间的联系。同样在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L199)中定义，如下：

```C
struct pool_workqueue {
	struct worker_pool	*pool;		/* I: the associated pool */
	struct workqueue_struct *wq;		/* I: the owning workqueue */
    ...
} __aligned(1 << WORK_STRUCT_FLAG_BITS);
```

### 3.2 工作队列调度过程

通过`DECLARE_WORK`宏或者`INIT_WORK`宏创建`work`后，我们需要把它放到`工作队列`中去。我们通过`queue_work`函数或者`queue_delayed_work`来实现，这两个函数在[include/linux/workqueue.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/workqueue.h#L505)中定义如下：

```C
static inline bool queue_work(struct workqueue_struct *wq,
                              struct work_struct *work)
{
    return queue_work_on(WORK_CPU_UNBOUND, wq, work);
}
...
...
static inline bool queue_delayed_work(struct workqueue_struct *wq,
				      struct delayed_work *dwork,
				      unsigned long delay)
{
	return queue_delayed_work_on(WORK_CPU_UNBOUND, wq, dwork, delay);
}
```

`queue_work`只是调用`queue_work_on`函数指定相应的处理器。注意这里给`queue_work_on`函数传递`WORK_CPU_UNBOUND`参数。`WORK_CPU_UNBOUND`是代表队列任务绑定到处理器的枚举成员，该枚举在[include/linux/workqueue.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/workqueue.h#L62)中定义。`queue_work_on`函数测试并设置任务的`WORK_STRUCT_PENDING_BIT`标志位，然后调用`__queue_work`函数，如下：

```C
bool queue_work_on(int cpu, struct workqueue_struct *wq,
		   struct work_struct *work)
{
	bool ret = false;
	unsigned long flags;

	local_irq_save(flags);

	if (!test_and_set_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))) {
		__queue_work(cpu, wq, work);
		ret = true;
	}

	local_irq_restore(flags);
	return ret;
}
```

`__queue_work`函数在同一个文件中实现，如下：

```C
static void __queue_work(int cpu, struct workqueue_struct *wq,
                         struct work_struct *work)
{
	struct pool_workqueue *pwq;
	struct worker_pool *last_pool;
	struct list_head *worklist;
	unsigned int work_flags;
	unsigned int req_cpu = cpu;
    ...
    ...
retry:
	if (wq->flags & WQ_UNBOUND) {
		if (req_cpu == WORK_CPU_UNBOUND)
			cpu = wq_select_unbound_cpu(raw_smp_processor_id());
		pwq = unbound_pwq_by_node(wq, cpu_to_node(cpu));
	} else {
		if (req_cpu == WORK_CPU_UNBOUND)
			cpu = raw_smp_processor_id();
		pwq = per_cpu_ptr(wq->cpu_pwqs, cpu);
	}
	last_pool = get_work_pool(work);
	if (last_pool && last_pool != pwq->pool) {
		struct worker *worker;

		if (worker && worker->current_pwq->wq == wq) {
            ...
			pwq = worker->current_pwq;
		} else {
            ...
		}
	} else {
        ...
	}
    ...
    ...
	insert_work(pwq, work, worklist, work_flags);
}
```

`__queue_work`函数根据`workqueue`标记和`raw_smp_processor_id`获取到当前的CPU后，获取和`work_struct`对应的`pool_workqueue`后，调用`insert_work`函数将`work`插入到`worklist`中。如下：

```C
static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
			struct list_head *head, unsigned int extra_flags)
{
	struct worker_pool *pool = pwq->pool;
	set_work_pwq(work, pwq, extra_flags);
	list_add_tail(&work->entry, head);
	get_pwq(pwq);

	smp_mb();

	if (__need_more_worker(pool))
		wake_up_worker(pool);
}
```

`wake_up_worker`函数从`pool`中获取空闲的任务后，将任务状态设置成`TASK_NORMAL`状态。`worker_pool`和`worker`对应，唤起对应的worker线程。

### 3.3 工作队列执行过程

现在我们可以创建`works`和`workqueue`，接下来，我们需要知道它们是如何执行的。就像前面提到的，所有的`works`都会在`kworker`内核线程中执行。`kwoker`线程在创建时执行`worker_thread`函数，`worker_thread`函数在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L2357)中实现，如下：

```C
static int worker_thread(void *__worker)
{
	struct worker *worker = __worker;
	struct worker_pool *pool = worker->pool;

	set_pf_worker(true);
woke_up:
    ...
    ...
recheck:
    ...
    ...
    do {
		struct work_struct *work =
			list_first_entry(&pool->worklist,
					 struct work_struct, entry);

		pool->watchdog_ts = jiffies;

		if (likely(!(*work_data_bits(work) & WORK_STRUCT_LINKED))) {
			/* optimization path, not strictly necessary */
			process_one_work(worker, work);
			if (unlikely(!list_empty(&worker->scheduled)))
				process_scheduled_works(worker);
		} else {
			move_linked_works(work, &worker->scheduled, NULL);
			process_scheduled_works(worker);
		}
	} while (keep_working(pool));

sleep:
    ...
    ...
	goto woke_up;
}
```

`worker_thread`函数判断`pool`可以执行时，调用`process_one_work`函数执行`work`，如下：

```C
static void process_one_work(struct worker *worker, struct work_struct *work)
__releases(&pool->lock)
__acquires(&pool->lock)
{
    ...
    ...
	worker->current_func = work->func;
    ...
	worker->current_func(work);
    ...
	list_del_init(&work->entry);
    ...
    ...
}
```

`process_one_work`函数执行时，将`work`的执行函数赋值给`worker`后，通过`worker`调用执行。在执行完成后调用`list_del_init`函数从`workqueue`中移除。

## 4 结束语

本文继续深入分析外部中断的实现过程，分析了三种延后中断的实现方式`软中断`，`tasklet` 和`工作队列`。现在已经完成了所有中断的分析。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
