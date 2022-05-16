# CPU掩码

## 0 介绍

`Cpumasks` 是Linux内核提供的保存系统CPU信息的特殊方法。包含 `Cpumasks` 操作API相关的源码和头文件如下：

* [include/linux/cpumask.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/cpumask.h)
* [lib/cpumask.c](https://github.com/torvalds/linux/blob/v5.4/lib/cpumask.c)
* [kernel/cpu.c](https://github.com/torvalds/linux/blob/v5.4/kernel/cpu.c)

正如 [include/linux/cpumask.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/cpumask.h) 注释：Cpumasks 提供了适用于表示系统中CPU集合的位图，每个bit表示一个CPU。

我们已经在 [Kernel entry point](http://0xax.gitbooks.io/linux-insides/content/Initialization/linux-initialization-4.html) 部分，`boot_cpu_init` 函数中看到了一些 cpumask的内容。这个函数将第一个启动的 cpu 上线、激活等等……：

```C
set_cpu_online(cpu, true);
set_cpu_active(cpu, true);
set_cpu_present(cpu, true);
set_cpu_possible(cpu, true);
```

在分析这些函数的实现之前，我们来分析下这些掩码。

`cpu_possible` 表示在系统启动时任意时刻都可插入的 cpu ID 的集合。换句话说，这个集合包含系统中最大的CPU数量。即，通过 `CONFIG_NR_CPUS` 内核配置选项设置的`NR_CPUS`值。

`cpu_present` 表示当前插入的 CPU。`cpu_online` 是 `cpu_present` 的子集，表示可调度的 CPU。最后一个掩码是 `cpu_active`，表示Linux内核中任务可以运行的CPU。

这些掩码依赖于 `CONFIG_HOTPLUG_CPU` 内核配置选项，在该选项禁用时，`possible == present` 并且 `active == online`。这些函数的实现很相似，每个函数都会检测第二个参数，如果为 `true`，就调用 `cpumask_set_cpu` ，否则调用 `cpumask_clear_cpu`。

## 1 `cpumask`的定义

有两种方法定义 `cpumask`。第一种是用 `cpumask_t`，定义如下：

```C
typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;
```

它封装了 `cpumask` 结构，其包含了一个位掩码 `bits` 字段。`DECLARE_BITMAP` 宏有两个参数：`name` 和 `bits` 的数量，它的实现非常简单，以给定名称创建了一个 `unsigned long` 数组。如下：

```C
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]
```

其中, `BITS_TO_LONGS` 的定义如下：

```C
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
...
...
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
```

因为我们关注于`x86_64`架构，`unsigned long`是8字节大小。因此，一个`unsigned long`最多可以表示64个CPU。

`NR_CPUS` 宏表示的是系统中 CPU 的数目，依赖于在 [include/linux/threads.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/threads.h#L21) 中定义的 `CONFIG_NR_CPUS` 宏，如下：

```C
#ifndef CONFIG_NR_CPUS
        #define CONFIG_NR_CPUS  1
#endif

#define NR_CPUS         CONFIG_NR_CPUS
```

第二种定义 `cpumask` 的方法是直接使用宏 `DECLARE_BITMAP` 和 `to_cpumask` 宏，后者将给定的位图转化为 `struct cpumask *`：

```C
#define to_cpumask(bitmap)                                              \
        ((struct cpumask *)(1 ? (bitmap)                                \
                            : (void *)sizeof(__check_is_bitmap(bitmap))))
```

可以看到这里的三目运算符每次总是 `true`。`__check_is_bitmap` 内联函数每次都是返回 `1`，定义为：

```C
static inline int __check_is_bitmap(const unsigned long *bitmap)
{
        return 1;
}
```

我们需要它只是因为，编译时检测一个给定的 `bitmap` 是一个位图，换句话说，它检测一个 `bitmap` 是否有 `unsigned long *` 类型。因此我们传递 `cpu_possible_bits` 给宏 `to_cpumask` ，将 `unsigned long` 数组转换为 `struct cpumask *`。

## 2 `cpumask`的API

因为我们可以用其中一个方法来定义 cpumask，Linux 内核提供了用于操作cpumask的API。我们来研究下其中一个函数，例如 `set_cpu_active`。

`set_cpu_active`函数在[include/linux/cpumask.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/cpumask.h#L841)中实现。这个函数有两个参数：`cpu` -- CPU索引 和 `active` -- CPU状态。如下：

```C
static inline void
set_cpu_active(unsigned int cpu, bool active)
{
	if (active)
		cpumask_set_cpu(cpu, &__cpu_active_mask);
	else
		cpumask_clear_cpu(cpu, &__cpu_active_mask);
}
```

该函数首先检测第二个 `active` 参数并调用依赖它的 `cpumask_set_cpu` 或 `cpumask_clear_cpu`。

### 2.1 `cpumask_set_cpu` 函数

这里我们可以看到在中 `cpumask_set_cpu` 的第二个参数转换为 `struct cpumask *`。在我们的例子中是位图 `__cpu_active_mask`，定义如下：

```C
struct cpumask __cpu_active_mask __read_mostly;
```

`cpumask_set_cpu`函数仅调用 `set_bit` 函数：

```C
static inline void cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
	set_bit(cpumask_check(cpu), cpumask_bits(dstp));
}
```

`set_bit` 函数需要两个参数，设置了一个给定位（第一个参数）的内存（第二个参数或 `__cpu_active_mask` 位图）。在调用 `set_bit` 之前，它的两个参数会传递给 `cpumask_check` 和 `cpumask_bits`。

`cpumask_check` 函数在 `CONFIG_DEBUG_PER_CPU_MAPS` 选项开启的情况下，检查给定的CPU序号是否超过设置值，之后返回给定的参数。如下：

```C
static inline void cpu_max_bits_warn(unsigned int cpu, unsigned int bits)
{
#ifdef CONFIG_DEBUG_PER_CPU_MAPS
	WARN_ON_ONCE(cpu >= bits);
#endif /* CONFIG_DEBUG_PER_CPU_MAPS */
}

static inline unsigned int cpumask_check(unsigned int cpu)
{
	cpu_max_bits_warn(cpu, nr_cpumask_bits);
	return cpu;
}
```

`cpumask_bits` 宏返回传入 `struct cpumask *` 结构的 `bits` 字段，如下：

```C
#define cpumask_bits(maskp) ((maskp)->bits)
```

现在让我们看下 `set_bit` 的实现，`set_bit` 函数在 [include/asm-generic/bitops-instrumented.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/bitops-instrumented.h#L26) 中定义，调用 `arch_set_bit` 函数。如下：

```C
static inline void set_bit(long nr, volatile unsigned long *addr)
{
	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
	arch_set_bit(nr, addr);
}
```

`arch_set_bit` 函数在 [arch/x86/include/asm/bitops.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/bitops.h#L52) 中实现，如下：

```C
static __always_inline void
arch_set_bit(long nr, volatile unsigned long *addr)
{
	if (__builtin_constant_p(nr)) {
		asm volatile(LOCK_PREFIX "orb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((u8)CONST_MASK(nr))
			: "memory");
	} else {
		asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
	}
}
```

`__builtin_constant_p` 检查给定参数是否编译时恒定变量。因为我们的 `cpu` 不是编译时恒定变量，将会执行 `else` 分支：

```C
		asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
```

让我们试着一步一步来理解它如何工作的：

`LOCK_PREFIX`是个 x86 `lock` 指令。这个指令告诉 CPU 当指令执行时占据系统总线。这允许 CPU 同步内存访问，防止多核（或多设备 - 比如 DMA 控制器）并发访问同一个内存单元。

`RLONG_ADDR`转换给定参数至 `(*(volatile long *)` 并且加 `m` 约束。如下：

```C
#define RLONG_ADDR(x)			 "m" (*(volatile long *) (x))
```

`memory`告诉编译器汇编代码执行内存读或写到某些项，而不是那些输入或输出操作数（例如，访问指向输出参数的内存）。

`Ir`表示寄存器操作数。

`bts`指令设置对应bit位的值。

在调用 `cpumask_set_cpu` 函数时，所以我们传递`cpu`号（我们的例子中为 0），传递给 `set_bit` 执行后，最终设置了在 `__cpu_active_mask` cpumask 中的 0 位。这意味着第一个 cpu 此时启用了。

### 2.2 `cpumask_clear_cpu` 函数

`cpumask_clear_cpu` 函数功能和 `cpumask_set_cpu` 函数功能相反，它清除CPU位图中状态。如下：

```C
static inline void cpumask_clear_cpu(int cpu, struct cpumask *dstp)
{
	clear_bit(cpumask_check(cpu), cpumask_bits(dstp));
}
...
...
static inline void clear_bit(long nr, volatile unsigned long *addr)
{
	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
	arch_clear_bit(nr, addr);
}
...
...
static __always_inline void
arch_clear_bit(long nr, volatile unsigned long *addr)
{
	if (__builtin_constant_p(nr)) {
		asm volatile(LOCK_PREFIX "andb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((u8)~CONST_MASK(nr)));
	} else {
		asm volatile(LOCK_PREFIX __ASM_SIZE(btr) " %1,%0"
			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
	}
}
```

可以看到，最终调用 `arch_clear_bit` 函数。和 `arch_set_bit` 函数类似，`arch_clear_bit` 函数调用 `btr` 指令复位对应bit位的值。

### 2.3 `cpumask`的其他API

除了`set_cpu_*`系列的API，还提供了其他操作`cpumask`的API。`cpumaks` 提供了一系列宏来得到不同状态 CPUs 序号。例如：

```C
#define num_possible_cpus()	cpumask_weight(cpu_possible_mask)
```

这个宏返回 `possible` CPU数量。它调用`cpumask_weight` 函数读取 `cpu_possible_mask` 位图。`cpumask_weight` 函数调用 `bitmap_weight` 函数，如下：

```C
static inline unsigned int cpumask_weight(const struct cpumask *srcp)
{
	return bitmap_weight(cpumask_bits(srcp), nr_cpumask_bits);
}
```

`bitmap_weight` 函数需要两个参数：`src` -- 位图，`nbits` -- 位图的bit数量。`bitmap_weight`函数计算给定位图的位数。

除了 `num_possible_cpus`，cpumask 还提供了所有 CPU 状态的宏：

* num_present_cpus;
* num_active_cpus;
* cpu_online;
* cpu_possible；
* ...

除此之外，Linux内核提供的下述操作`cpumask`的API：

* `for_each_cpu` - 遍历掩码中每个cpu;
* `for_each_cpu_not` -- 遍历不在掩码中cpu;
* `cpumask_clear_cpu` - 清除掩码中的cpu;
* `cpumask_test_cpu` - 判读CPU是否在掩码中;
* `cpumask_setall` - 设置掩码中的所有cpu;
* `cpumask_size` - 返回分配 'struct cpumask' 字节数大小;

还有很多。

## 3 结束语

在这一部分我们分析了Linux内核中`cpumask`相关内容，分析了`cpumask` 的定义和主要的API。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
