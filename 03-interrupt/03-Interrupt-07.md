# 中断和中断处理 （第七部分）

## 0 外部中断介绍

在上一部分中，我们深入了解了处理器生成的异常。接下来的部分，我们将继续深入中断处理，将从外部硬件中断开始。在上一部分，我们介绍了[arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/traps.c#L925)文件中的`trap_init`函数，接下来，我们介绍[init/main.c]文件中的`early_irq_init`函数。

中断是硬件或软件通过[IRQ(Interrupt Request Line)](https://en.wikipedia.org/wiki/Interrupt_request_(PC_architecture))总线发送的信号。外部硬件中断允许设备（如：鼠标、键盘等）指示它需要处理器的注意。处理器接收到中断请求后，它将暂时停止执行当前正在运行的程序，并调用依赖于中断的特殊程序，在处理完中断后，处理器恢复中断的程序。我们已经知道这个程序叫做中断处理程序（或者 中断服务程序（Interrupt Service Routine， ISR）），ISR可以在内存中固定位置的中断向量表中找到。在引导和初始化阶段，Linux内核识别机器中的所有设备，并将适当的中断处理程序加载到中断表中。正如我们在前面部分看到的，大部分异常通过发送[Unix 信号](https://en.wikipedia.org/wiki/Unix_signal)到中断的进程来完成中断处理的，这就是内核可以快速处理异常的原因。不幸的是，我们不能将这种方法用于外部硬件中断，因为信号通常在与之相关的进程被挂起后（有时是很久之后）才到达。所以，向当前进程发送信号是没有意义的。

外部中断处理取决于中断类型，包括：I/O中断、定时器中断、处理器间中断。通常，I/O中断处理程序必须足够灵活，同时可以服务于多个设备。例如，PCI总线架构下，多个设备可能共享同一个IRQ总线。在最简单的方式，当I/O中断发生时，Linux内核必须执行以下操作：

* 保存IRQ的值和寄存器的内容保存到内核栈上；
* 向正在提供中断服务的IRQ总线发送确认信息到硬件控制器；
* 执行与硬件设备相关的中断服务程序（ISR）；
* 恢复寄存器并从中断中返回；

现在，我们知道了这些理论，我们从`early_irq_init`函数开始。`early_irq_init`函数在[kernel/irq/irqdesc.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/irqdesc.c#L519)中实现，这个函数进行`irq_desc`结构的早期初始化。`irq_desc`结构是Linux内核中断管理的基础，一个同名的数组`struct irq_desc irq_desc[NR_IRQS]`，追踪Linux内核中每个中断请求源。该结构在[include/linux/irqdesc.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irqdesc.h#L56)中定义，它的定义依赖于`CONFIG_SPARSE_IRQ`内核配置选项，该选项启用对稀疏IRQ的支持。`irq_desc`结构包含许多不同的字段，主要的字段如下：

* irq_common_data - 传递到芯片功能的每个IRQ和芯片数据；
* status_use_accessors - 中断源的状态；
* kstat_irqs - 每个CPU的irq统计状态；
* handle_irq - 高级中断事件处理程序；
* action - IRQ触发时调用的中断服务程序；
* irq_count - IRQ总线上中断发生的计数；
* depth - 禁用中断的次数；
* last_unhandled - 未处理中断的计时器；
* irqs_unhandled - 未处理中断的计数；
* lock - 顺序访问IRQ的自旋锁；
* pending_mask - 重新分配中断时可用的CPU；
* owner - 中断描述符的所有者。中断描述符可以从模块中分配。通过模块中分配时，需要增加引用计数。
* ...

## 1 早期外部中断初始化

`early_irq_init`函数依赖于`CONFIG_SPARSE_IRQ`内核配置选项。现在，我们先考虑`CONFIG_SPARSE_IRQ`内核配置选项没有设置的情况。函数实现如下：

```C
int __init early_irq_init(void)
{
	int count, i, node = first_online_node;
	struct irq_desc *desc;
    ...
    ...
}
```

### 1.1 获取第一个在线节点（`first_online_node`）

`node`表示在线[NUMA](https://en.wikipedia.org/wiki/Non-uniform_memory_access)节点，它取决于`MAX_NUMNODES`值，`MAX_NUMNODES`值取决于`CONFIG_NODES_SHIFT`内核配置参数。如下：

```C
#ifdef CONFIG_NODES_SHIFT
#define NODES_SHIFT     CONFIG_NODES_SHIFT
#else
#define NODES_SHIFT     0
#endif

#define MAX_NUMNODES    (1 << NODES_SHIFT)
```

`first_online_node`宏取决于`MAX_NUMNODES`值，如下：

```C
#if MAX_NUMNODES > 1
#define first_online_node	first_node(node_states[N_ONLINE])
#else
#define first_online_node	0
#endif
```

`node_states`是个枚举值，表示节点的状态，在[include/linux/nodemask.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/nodemask.h#L391)中定义。`MAX_NUMNODES`为0或1时，`first_online_node`为0；`MAX_NUMNODES`大于1时，`node_states[N_ONLINE]`值为1,`first_node`宏展开后调用`__first_node`函数，返回最小值或者第一个在线的节点，如下：

```C
#define first_node(src) __first_node(&(src))
static inline int __first_node(const nodemask_t *srcp)
{
	return min_t(int, MAX_NUMNODES, find_first_bit(srcp->bits, MAX_NUMNODES));
}
```

### 1.2 IRQ默认亲和性设置（`init_irq_default_affinity`）

我们知道，当硬件（例如：磁盘控制器或键盘）需要处理器注意时，它会引起中断。中断告诉处理器发生了什么，处理器应该中断当前进程并处理传入事件。为了防止多个设备发送相同的中断，建立了IRQ系统，为系统中每个设备都分配了一个唯一的IRQ。Linux内核可以将某些IRQs分配给特定的处理器，称之为`SMP IRQ affinity`，它允许你控制系统如何响应各种硬件事件（这也是为什么只有在`CONFIG_SMP`内核配置选项启用时才具有特定实现的原因）。

`init_irq_default_affinity`函数在同一个文件中实现，其实现取决于`CONFIG_SMP`内核配置选项，在启用时，设置`irq_default_affinity`的cpumask结构变量值。如下：

```C
#if defined(CONFIG_SMP)
static void __init init_irq_default_affinity(void)
{
	if (!cpumask_available(irq_default_affinity))
		zalloc_cpumask_var(&irq_default_affinity, GFP_NOWAIT);
	if (cpumask_empty(irq_default_affinity))
		cpumask_setall(irq_default_affinity);
}
#else
static void __init init_irq_default_affinity(void)
{
}
#endif
```

### 1.3 打印NR_IRQS

接下来，我们可以看到`printk`输出，打印`NR_IRQS`，如下：

```C
	printk(KERN_INFO "NR_IRQS: %d\n", NR_IRQS);
```

通过`dmesg`可以找到如下信息：

```C
~$ dmesg | grep NR_IRQS
[    0.000000] NR_IRQS:4352
```

`NR_IRQS`是`irq`描述符的最大数量，或者系统中的最大中断数量。该值在[arch/x86/include/asm/irq_vectors.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/irq_vectors.h#L133)中定义，取决于`CONFIG_X86_IO_APIC`和`CONFIG_PCI_MSI`内核配置选项状态。如下：

```C
#define NR_IRQS_LEGACY			16

#define CPU_VECTOR_LIMIT		(64 * NR_CPUS)
#define IO_APIC_VECTOR_LIMIT		(32 * MAX_IO_APICS)

#if defined(CONFIG_X86_IO_APIC) && defined(CONFIG_PCI_MSI)
#define NR_IRQS						\
	(CPU_VECTOR_LIMIT > IO_APIC_VECTOR_LIMIT ?	\
		(NR_VECTORS + CPU_VECTOR_LIMIT)  :	\
		(NR_VECTORS + IO_APIC_VECTOR_LIMIT))
#elif defined(CONFIG_X86_IO_APIC)
#define	NR_IRQS				(NR_VECTORS + IO_APIC_VECTOR_LIMIT)
#elif defined(CONFIG_PCI_MSI)
#define NR_IRQS				(NR_VECTORS + CPU_VECTOR_LIMIT)
#else
#define NR_IRQS				NR_IRQS_LEGACY
#endif
```

`NR_CPUS`的值为`CONFIG_NR_CPUS`内核配置选项，表示支持的处理器数量。`MAX_IO_APICS`在[arch/x86/include/asm/apicdef.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/apicdef.h#L151)中定义，如下：

```C
#ifdef CONFIG_X86_32
# define MAX_IO_APICS 64
# define MAX_LOCAL_APIC 256
#else
# define MAX_IO_APICS 128
# define MAX_LOCAL_APIC 32768
#endif
```

即，`x86_64`下`IO_APIC_VECTOR_LIMIT`值为4096。在`CONFIG_NR_CPUS`配置为8的情况下,`CPU_VECTOR_LIMIT`值为512。 在`CONFIG_X86_IO_APIC`和`CONFIG_PCI_MSI`内核配置选项都开启的情况下，`NR_IRQS`取决于`CPU_VECTOR_LIMIT`和`IO_APIC_VECTOR_LIMIT`之间的较大值，即`IO_APIC_VECTOR_LIMIT`，因此`NR_IRQS`值为4352。在`CONFIG_X86_IO_APIC`和`CONFIG_PCI_MSI`内核配置选项都关闭的情况下，`NR_IRQS`值为`NR_IRQS_LEGACY`。

### 1.4 IRQ描述符（`irq_desc`）初始化

#### 1.4.1 IRQ描述符定义

接下来，我们通过`ARRAY_SIZE`宏计算IRQ描述符数组（`irq_desc`）的数量。`irq_desc`数组在同一个文件中定义，如下：

```C
struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned_in_smp = {
	[0 ... NR_IRQS-1] = {
		.handle_irq	= handle_bad_irq,
		.depth		= 1,
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(irq_desc->lock),
	}
};
```

`irq_desc`是`irq`描述符的数组，包含三个已经初始化的字段：

* `handle_irq` - 如上面描述的那样，这个字段是高级irq事件处理程序。目前，我们初始化为[kernel/irq/handle.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/handle.c#L31)中的`handle_bad_irq`函数。`handle_bad_irq`函数处理虚假的和没有中断实现的irq；
* `depth` - IRQ总线启用时为0；>0时，该中断至少被禁用一次；
* `lock` - 顺序访问IRQ描述符的自旋锁；

#### 1.4.2 IRQ描述符初始化

在我们计算中断数量后，通过循环来初始化`irq_desc`，如下：

```C
	for (i = 0; i < count; i++) {
		desc[i].kstat_irqs = alloc_percpu(unsigned int);
		alloc_masks(&desc[i], node);
		raw_spin_lock_init(&desc[i].lock);
		lockdep_set_class(&desc[i].lock, &irq_desc_lock_class);
		mutex_init(&desc[i].request_mutex);
		desc_set_defaults(i, &desc[i], node, NULL, NULL);
	}
```

我们遍历所有的中断描述符，并执行如下操作：

首先，通过`alloc_percpu`宏分配一个`percpu`变量用来`irq`内核统计。该宏为系统上的每个处理器分配给定类型的示例。可以在用户空间下通过`/proc/stat`来访问内核统计信息，第六列显示中断的统计信息，如下：

```C
~$ cat /proc/stat
cpu  207907 68 53904 5427850 14394 0 394 0 0 0
cpu0 25881 11 6684 679131 1351 0 18 0 0 0
cpu1 24791 16 5894 679994 2285 0 24 0 0 0
cpu2 26321 4 7154 678924 664 0 71 0 0 0
cpu3 26648 8 6931 678891 414 0 244 0 0 0
...
...
...
```

在此之后，我们为给定的irq描述符关联分配cpumask，初始化[自旋锁(SpinLock)](https://en.wikipedia.org/wiki/Spinlock)。在之后的[临界区(Critical section)](https://en.wikipedia.org/wiki/Critical_section)，通过调用`raw_spin_lock`来获取锁，通过`raw_spin_unlock`来释放锁。下一步，我们调用`lockdep_set_class`宏为每个中断描述符的锁来设置锁验证器`irq_desc_lock_class`；调用`mutex_init`宏来初始化irq描述符的互斥量。

#### 1.4.3 IRQ描述符填充

最后，我们调用`desc_set_defaults`函数来填充`irq_desc`剩余的字段。`desc_set_defaults`函数在同一个文件中实现，该函数需要5个参数，`irq` - irq号；`desc` - 中断描述符；`node` - 在线的`NUMA`节点；`affinity` - CPU亲和量； `owner` - 中断的所有者。

* 填充信息`irq_data`
  
`desc_set_defaults`函数填充中断号、irq芯片、芯片函数使用的平台相关的per-chip私有数据、`irq_chip`函数使用的per-IRQ数据、[MSI](https://en.wikipedia.org/wiki/Message_Signaled_Interrupts)描述符使用的per-chip和芯片数据。如下：

```C
	desc->irq_common_data.handler_data = NULL;
	desc->irq_common_data.msi_desc = NULL;

	desc->irq_data.common = &desc->irq_common_data;
	desc->irq_data.irq = irq;
	desc->irq_data.chip = &no_irq_chip;
	desc->irq_data.chip_data = NULL;
```

`irq_data.chip`结构为`struct irq_chip`，在[include/linux/irq.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irq.h#L449)中定义。提供了IRQ控制器驱动访问的通用API，如`irq_startup`，`irq_shutdown`等函数。这里设置为`no_irq_chip`，`no_irq_chip`在[kernel/irq/dummychip.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/dummychip.c#L39)中定义，如下：

```C
struct irq_chip no_irq_chip = {
	.name		= "none",
	.irq_startup	= noop_ret,
	.irq_shutdown	= noop,
	.irq_enable	= noop,
	.irq_disable	= noop,
	.irq_ack	= ack_bad,
	.flags		= IRQCHIP_SKIP_SET_WAKE,
};
```

* 设置IRQ描述符状态

接下来，我们设置IRQ描述为默认状态，并设置IRQ禁用和屏蔽状态。如下：

```C
	irq_settings_clr_and_set(desc, ~0, _IRQ_DEFAULT_INIT_FLAGS);
	irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
	irqd_set(&desc->irq_data, IRQD_IRQ_MASKED);
```

`irq_settings_clr_and_set`函数在[kernel/irq/settings.h](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/settings.h#L38)中实现，设置irq总线状态，如下：

```C
static inline void
irq_settings_clr_and_set(struct irq_desc *desc, u32 clr, u32 set)
{
	desc->status_use_accessors &= ~(clr & _IRQF_MODIFY_MASK);
	desc->status_use_accessors |= (set & _IRQF_MODIFY_MASK);
}
```

`_IRQF_MODIFY_MASK`即`IRQF_MODIFY_MASK`，`IRQF_MODIFY_MASK`在[include/linux/irq.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irq.h#L102)中定义，如下：

```C
#define IRQF_MODIFY_MASK	\
	(IRQ_TYPE_SENSE_MASK | IRQ_NOPROBE | IRQ_NOREQUEST | \
	 IRQ_NOAUTOEN | IRQ_MOVE_PCNTXT | IRQ_LEVEL | IRQ_NO_BALANCING | \
	 IRQ_PER_CPU | IRQ_NESTED_THREAD | IRQ_NOTHREAD | IRQ_PER_CPU_DEVID | \
	 IRQ_IS_POLLED | IRQ_DISABLE_UNLAZY)
```

`irqd_set`设置`irq_common_data.state_use_accessors`字段bit掩码值。

* 设置irq中断处理程序

接下来，我们设置`handle_irq`为`handle_bad_irq`（在没有硬件初始化时，默认设置该中断处理程序）；设置`depth`为1，即禁用该IRQ；重置中断处理和未处理的计数。如下：

```C
	desc->handle_irq = handle_bad_irq;
	desc->depth = 1;
	desc->irq_count = 0;
	desc->irqs_unhandled = 0;
	desc->tot_count = 0;
	desc->name = NULL;
	desc->owner = owner;
```

* 统计计数清零

接下来，我们使用`for_each_possible_cpu`宏遍历所有可用的CPU，将IRQ描述符内核统计信息设置为0。如下：

```C
	for_each_possible_cpu(cpu)
		*per_cpu_ptr(desc->kstat_irqs, cpu) = 0;
```

* 中断描述符NUMA节点设置

接下来，调用`desc_smp_init`函数，初始化IRQ描述符的NUMA节点设置，包括设置默认SMP默认亲和力；在`CONFIG_GENERIC_PENDING_IRQ`内核配置选项开启的情况下，清除`pending_mask`。如下：

```C
static void desc_smp_init(struct irq_desc *desc, int node,
			  const struct cpumask *affinity)
{
	if (!affinity)
		affinity = irq_default_affinity;
	cpumask_copy(desc->irq_common_data.affinity, affinity);

#ifdef CONFIG_GENERIC_PENDING_IRQ
	cpumask_clear(desc->pending_mask);
#endif
#ifdef CONFIG_NUMA
	desc->irq_common_data.node = node;
#endif
}
```

### 1.5 平台早期IRQ初始化

在`early_irq_init`函数的最后，我们调用`arch_early_irq_init`函数进行平台相关IRQ早期初始化。`arch_early_irq_init`函数在[arch/x86/kernel/apic/vector.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/vector.c#L697)中实现。

#### 1.5.1 irq_domain初始化

`irq_domain`在[include/linux/irqdomain.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irqdomain.h#L160)中定义，用来描述硬件中断号和内存对象的转换关系。初始化过程如下：

```C
int __init arch_early_irq_init(void)
{
	struct fwnode_handle *fn;

	fn = irq_domain_alloc_named_fwnode("VECTOR");
	BUG_ON(!fn);
	x86_vector_domain = irq_domain_create_tree(fn, &x86_vector_domain_ops,
						   NULL);
	BUG_ON(x86_vector_domain == NULL);
	irq_set_default_host(x86_vector_domain);

	arch_init_msi_domain(x86_vector_domain);

	BUG_ON(!alloc_cpumask_var(&vector_searchmask, GFP_KERNEL));

	/*
	 * Allocate the vector matrix allocator data structure and limit the
	 * search area.
	 */
	vector_matrix = irq_alloc_matrix(NR_VECTORS, FIRST_EXTERNAL_VECTOR,
					 FIRST_SYSTEM_VECTOR);
	BUG_ON(!vector_matrix);

	return arch_early_ioapic_init();
}
```

`fwnode_handle`结构在[include/linux/fwnode.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/fwnode.h#L17)中定义，用来描述固件设备节点对象处理。`vector_matrix`用于中断向量限制查询区域。

#### 1.5.2 ioapci初始化

`arch_early_ioapic_init`函数在[arch/x86/kernel/apic/io_apic.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/io_apic.c#L253)中实现，进行[I/O APIC](https://en.wikipedia.org/wiki/Advanced_Programmable_Interrupt_Controller)早期初始化。如下：

```C
int __init arch_early_ioapic_init(void)
{
	int i;
	if (!nr_legacy_irqs())
		io_apic_irqs = ~0UL;
	for_each_ioapic(i)
		alloc_ioapic_saved_registers(i);
	return 0;
}
```

首先，调用`nr_legacy_irqs`函数检查传统中断数量，如果不存在[Intel 8259](https://en.wikipedia.org/wiki/Intel_8259)可编程中断（即，传统中断）时，将`io_apic_irqs`置为`0xffffffffffffffff`。

接下来，遍历所有的`I/O APICs`，调用`alloc_ioapic_saved_registers`函数为每个中断分配寄存器空间。`I/O APICs`在Linux内核中使用`ioapics`表示，在[arch/x86/kernel/apic/io_apic.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/io_apic.c#L105)定义，如下：

```C
static struct ioapic {
	/*
	 * # of IRQ routing registers
	 */
	int nr_registers;
	/*
	 * Saved state during suspend/resume, or while enabling intr-remap.
	 */
	struct IO_APIC_route_entry *saved_registers;
...
} ioapics[MAX_IO_APICS];
```

## 2 稀疏IRQ早期初始化

在本文的开始介绍过，`early_irq_init`函数实现依赖于`CONFIG_SPARSE_IRQ`内核配置选项。在上文中，我们描述了`CONFIG_SPARSE_IRQ`没有设置的情形。接下来，我们分析该配置项开启的情况。整个实现过程相似，但有些不同。在`early_irq_init`函数的开始，我们可以看到同样的变量定义、`init_irq_default_affinity`函数调用。如下：

```C
int __init early_irq_init(void)
{
	int i, initcnt, node = first_online_node;
	struct irq_desc *desc;

	init_irq_default_affinity();

    	/* Let arch update nr_irqs and return the nr of preallocated irqs */
	initcnt = arch_probe_nr_irqs();
	printk(KERN_INFO "NR_IRQS: %d, nr_irqs: %d, preallocated irqs: %d\n",
	       NR_IRQS, nr_irqs, initcnt);
    ...
}
```

### 2.1 计算irq数量

但是，接下来调用`arch_probe_nr_irqs`函数计算预先分配的irq的数量，该函数在[arch/x86/kernel/apic/vector.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/vector.c#L640)中实现。但是，什么是预分配的IRQ？在[PCI](https://en.wikipedia.org/wiki/Conventional_PCI)中有个替代的方式叫做[消息信号中断(Message Signaled Interrupts， MSI)](https://en.wikipedia.org/wiki/Message_Signaled_Interrupts)。和分配固定数量的中断请求不同，这个设备允许在内存特定位置记录消息，实际上在本地APIC(Local APIC)显示。MSI允许设备分配`1`, `2`, `4`, `8`, `16` 或者`32`个中断，`MSI-X`允许分配最多`2048`个中断。

现在，我们知道irqs能够预分配。接下来，来看`arch_probe_nr_irqs`函数的实现。首先，计算CPU中断向量的数量和MSI中断数量，如下：

```C
    int nr_irqs = NR_IRQS;
    ...
	int nr;
	if (nr_irqs > (NR_VECTORS * nr_cpu_ids))
		nr_irqs = NR_VECTORS * nr_cpu_ids;

	nr = (gsi_top + nr_legacy_irqs()) + 8 * nr_cpu_ids;
```

每个`APIC`使用它的ID和IRQ起始的偏移量来标识，叫做全局系统中断（Global System Interrupt，GSI）基址。`gsi_top`变量用来表示这个偏移量。通过[多处理器规范](https://en.wikipedia.org/wiki/MultiProcessor_Specification)中可以获取GSI基址。

接下来，根据`gsi_top`变量来更新`nr`，如下：

```C
#if defined(CONFIG_PCI_MSI)
	/*
	 * for MSI and HT dyn irq
	 */
	if (gsi_top <= NR_IRQS_LEGACY)
		nr +=  8 * nr_cpu_ids;
	else
		nr += gsi_top * 16;
#endif
```

最后，更新`nr_irqs`，并返回传统irqs的数量。如下：

```C
	if (nr < nr_irqs)
		nr_irqs = nr;

	return legacy_pic->probe();
```

`legacy_pic`在[arch/x86/include/asm/i8259.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/i8259.h#L70)中定义，表示同名的结构的变量，即：`struct legacy_pic *legacy_pic`，默认初始化为`struct legacy_pic default_legacy_pic`。

### 2.2 irq数量检查

接下来，打印IRQ数量信息，如下：

```C
	printk(KERN_INFO "NR_IRQS: %d, nr_irqs: %d, preallocated irqs: %d\n",
	       NR_IRQS, nr_irqs, initcnt);
```

再此之后，检查`nr_irqs`和`initcnt`的值，确保不大于irq最大允许的数量，如下：

```C
	if (WARN_ON(nr_irqs > IRQ_BITMAP_BITS))
		nr_irqs = IRQ_BITMAP_BITS;

	if (WARN_ON(initcnt > IRQ_BITMAP_BITS))
		initcnt = IRQ_BITMAP_BITS;

	if (initcnt > nr_irqs)
		nr_irqs = initcnt;
```

`IRQ_BITMAP_BITS`表示最大的irq数量，定义如下：

```C
#ifdef CONFIG_SPARSE_IRQ
# define IRQ_BITMAP_BITS	(NR_IRQS + 8196)
#else
# define IRQ_BITMAP_BITS	NR_IRQS
#endif
```

### 2.3 分配irq

接下来，逐项分配所需的中断描述符，并插入到`irq_desc_tree`的基树中。如下：

```C
	for (i = 0; i < initcnt; i++) {
		desc = alloc_desc(i, node, 0, NULL, NULL);
		set_bit(i, allocated_irqs);
		irq_insert_desc(i, desc);
	}
```

`alloc_desc`函数在同一个文件实现，在分配`struct irq_desc`结构后，初始化相关变量。整个过程和之前类似，初始化`kstat_irqs`, `lock`, `request_mutex`，调用`desc_set_defaults`函数初始化默认值。但，增加了`rcu`，`irq_data`和`kobj`的初始化。

### 2.4 平台早期IRQ初始化

最后，调用`arch_early_irq_init`函数初始化平台相关早期IRQ初始化。实现过程同上。

## 3 结束语

本文开始深入分析外部中断的实现过程。我们分析了早期IRQ初始化过程，包括：外部中断数量计算；外部中断描述符（irq_desc）的初始化，如：默认中断处理程序初始化等。在接下来的部分，我们继续深入分析外部中断。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
