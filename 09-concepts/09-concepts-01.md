# Per-CPU 变量

## 0 介绍

`Per-CPU` 变量是一项内核特性，从它的名字就可以理解这项特性的含义。我们可以创建一个变量，内核中的每个处理器上都会有这个变量的拷贝。本文，我们来分析这个特性，并试着去理解它是如何实现以及工作的。

## 1 定义Per-CPU变量

内核在[include\linux\percpu-defs.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/percpu-defs.h#L114)文件中提供了 per-cpu 变量相关的API。 我们先来看下 `per-cpu` 是如何定义的， `per-cpu` 变量通过 `DEFINE_PER_CPU` 宏来定义，如下：

```C
#define DEFINE_PER_CPU(type, name) \
        DEFINE_PER_CPU_SECTION(type, name, "")
```

可以看到它使用了 2 个参数：`type` 和 `name`，因此我们可以传入要创建变量的类型和名字来创建 per-cpu 变量，例如：

```C
DEFINE_PER_CPU(int, per_cpu_n)
```

`DEFINE_PER_CPU` 宏调用 `DEFINE_PER_CPU_SECTION` 宏，将两个参数和空字符串传递给后者。让我们来看下 `DEFINE_PER_CPU_SECTION` 的定义, `DEFINE_PER_CPU_SECTION` 依赖于 `ARCH_NEEDS_WEAK_PER_CPU` 内核配置选项，该选项表示架构平台需要弱定义。在`x86_64` 架构下，该选项禁用，使用正常的定义，如下：

```C
#define DEFINE_PER_CPU_SECTION(type, name, sec)				\
	__PCPU_ATTRS(sec) __typeof__(type) name
...
...
#define __PCPU_ATTRS(sec)						\
	__percpu __attribute__((section(PER_CPU_BASE_SECTION sec)))	\
	PER_CPU_ATTRIBUTES
```

其中`PER_CPU_BASE_SECTION`宏 和 `PER_CPU_ATTRIBUTES` 宏在[include\asm-generic\percpu.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/percpu.h#L53)中定义，如下：

```C
#ifndef PER_CPU_BASE_SECTION
#ifdef CONFIG_SMP
#define PER_CPU_BASE_SECTION ".data..percpu"
#else
#define PER_CPU_BASE_SECTION ".data"
#endif
#endif

#ifndef PER_CPU_ATTRIBUTES
#define PER_CPU_ATTRIBUTES
#endif
```

在`x86_64`架构平台下支持SMP，因此，当所有的宏展开之后，我们得到一个全局的 per-cpu 变量：

```C
__attribute__((section(".data..percpu"))) int per_cpu_n
```

这意味着我们在 `.data..percpu` 段有一个 `per_cpu_n` 变量，可以在 `vmlinux` 中找到它：

```bash
.data..percpu 00013a58  0000000000000000  0000000001a5c000  00e00000  2**12
              CONTENTS, ALLOC, LOAD, DATA
```

现在我们知道，当使用 `DEFINE_PER_CPU` 宏时，在 `.data..percpu` 段中就创建了一个 per-cpu 变量。

## 2 Per-CPU区域初始化

内核初始化时，调用 `setup_per_cpu_areas` 函数多次加载 `.data..percpu` 段，每个CPU加载一次。让我们来看下per-cpu区域初始化流程，它从 [init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L600) 中调用 `setup_per_cpu_areas` 函数开始，这个函数在 [arch/x86/kernel/setup_percpu.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup_percpu.c#L168)中定义，如下：

```C
void __init setup_per_cpu_areas(void)
{
	...
	...

	pr_info("NR_CPUS:%d nr_cpumask_bits:%d nr_cpu_ids:%u nr_node_ids:%u\n",
		NR_CPUS, nr_cpumask_bits, nr_cpu_ids, nr_node_ids);
	...
	...
	...
}
```

`setup_per_cpu_areas` 函数在开始输出内核配置中最大CPUs数量（通过`CONFIG_NR_CPUS`选项配置）、实际的CPU数量、`nr_cpumask_bits`数量、`NUMA`节点数量。我们可以在 `dmesg` 中看到这些信息：

```bash
~$ dmesg | grep percpu
[    0.378375] setup_percpu: NR_CPUS:8192 nr_cpumask_bits:4 nr_cpu_ids:4 nr_node_ids:1
```

### 2.1 分配第一个区域块

所有的per-cpu区域都是以块进行分配的，第一个块用于静态 per-cpu 变量。Linux 内核提供了第一个块分配方式的参数：`percpu_alloc`，我们可以在内核文档中读到它的说明。

```text
percpu_alloc=	选择要使用哪个 per-cpu 第一个块分配器。
		当前支持的类型是 "embed" 和 "page"。
        不同架构支持这些类型的子集或不支持。
        更多分配器的细节参考 mm/percpu.c 中的注释。
        这个参数主要是为了调试和性能比较的。
```

在[include\linux\percpu.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/percpu.h#L87)中，我们也可以看到分配的方式，如下：

```C
enum pcpu_fc {
	PCPU_FC_AUTO,
	PCPU_FC_EMBED,
	PCPU_FC_PAGE,

	PCPU_FC_NR,
};
```

在[mm/percpu.c](https://github.com/torvalds/linux/blob/v5.4/mm/percpu.c#L2489) 包含了这个命令行选项的处理函数：

```C
early_param("percpu_alloc", percpu_alloc_setup);
```

`percpu_alloc_setup` 函数根据 `percpu_alloc` 参数值设置 `pcpu_chosen_fc` 变量。`pcpu_chosen_fc`的默认分配器是 `auto`：

```C
enum pcpu_fc pcpu_chosen_fc __initdata = PCPU_FC_AUTO;
```

接下来，根据`pcpu_chosen_fc`类型来分配per-cpu的第一个区域块。Linux内核优先使用`embed`分配器，在指定`page`分配器或`embed`分配器失败的情况下，使用`page`分配器。如下：

```C
	rc = -EINVAL;
	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
		const size_t dyn_size = PERCPU_MODULE_RESERVE +
			PERCPU_DYNAMIC_RESERVE - PERCPU_FIRST_CHUNK_RESERVE;
		size_t atom_size;

#ifdef CONFIG_X86_64
		atom_size = PMD_SIZE;
#else
		atom_size = PAGE_SIZE;
#endif
		rc = pcpu_embed_first_chunk(PERCPU_FIRST_CHUNK_RESERVE,
					    dyn_size, atom_size,
					    pcpu_cpu_distance,
					    pcpu_fc_alloc, pcpu_fc_free);
		if (rc < 0)
			pr_warning("%s allocator failed (%d), falling back to page size\n",
				   pcpu_fc_names[pcpu_chosen_fc], rc);
	}
	if (rc < 0)
		rc = pcpu_page_first_chunk(PERCPU_FIRST_CHUNK_RESERVE,
					   pcpu_fc_alloc, pcpu_fc_free,
					   pcpup_populate_pte);
```

如果采用`embed`分配器方式，会将第一个per-cpu块嵌入到`memblock`的bootmem中。这种方式通过调用`pcpu_embed_first_chunk`函数来实现的，传递给该函数的参数如下：

* `PERCPU_FIRST_CHUNK_RESERVE` - 为静态变量 `per-cpu` 保留空间的大小；
* `dyn_size` - 动态分配的最少空闲字节；
* `atom_size` - 所有的分配都是这个的整数倍，并以此对齐；
* `pcpu_cpu_distance` - 决定 cpus 距离的回调函数；
* `pcpu_fc_alloc` - 分配 `percpu` 页的函数；
* `pcpu_fc_free` - 释放 `percpu` 页的函数。

如果采用`page`分配器方式，第一个per-cpu块以内存页的方式进行分配，通过`pcpu_page_first_chunk` 函数来实现。

### 2.2 设置Per-CPU区域

在`per-cpu`区域准备完成后，遍历所有的CPU，设置每个CPU的区域。如下：

```C
	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
	for_each_possible_cpu(cpu) {
		per_cpu_offset(cpu) = delta + pcpu_unit_offsets[cpu];
		per_cpu(this_cpu_off, cpu) = per_cpu_offset(cpu);
		per_cpu(cpu_number, cpu) = cpu;
		setup_percpu_segment(cpu);
		setup_stack_canary_segment(cpu);

#ifdef CONFIG_X86_LOCAL_APIC
		per_cpu(x86_cpu_to_apicid, cpu) =
			early_per_cpu_map(x86_cpu_to_apicid, cpu);
		per_cpu(x86_bios_cpu_apicid, cpu) =
			early_per_cpu_map(x86_bios_cpu_apicid, cpu);
		per_cpu(x86_cpu_to_acpiid, cpu) =
			early_per_cpu_map(x86_cpu_to_acpiid, cpu);
#endif
		...
		...
		...
		if (!cpu)
			switch_to_new_gdt(cpu);
	}
```

可以看到，我们为`percpu`设置偏移量、段（只针对`x86`系统）、栈保护值后，将前面的数据从数组移到 `per-cpu` 变量（如： `x86_cpu_to_apicid`, `x86_bios_cpu_apicid` 等等）。

当内核完成初始化进程后，我们就有N个 `.data..percpu` 段（ N 是CPU的数量）。启动处理器使用 `DEFINE_PER_CPU` 宏来创建未初始化的变量。

## 3 Per-CPU变量操作API

内核在[include/linux/percpu-defs.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/percpu-defs.h#L276)提供了一些操作 per-cpu 变量的API：

* per_cpu_ptr(ptr, cpu)
* get_cpu_var(var)
* put_cpu_var(var)

### 3.1 Per-CPU变量典型用法

让我们来看看 `get_cpu_var` 和 `put_cpu_var` 的实现：

```C
#define get_cpu_var(var)						\
(*({									\
	preempt_disable();						\
	this_cpu_ptr(&var);						\
}))

#define put_cpu_var(var)						\
do {									\
	(void)&(var);							\
	preempt_enable();						\
} while (0)
```

Linux 内核是抢占式的，获取 `per-cpu` 变量需要我们知道内核运行在哪个处理器上。因此，在访问 per-cpu 变量时，当前代码不能被抢占，不能移到其它的 CPU。这就是为什么首先调用 `preempt_disable` 函数然后调用 `this_cpu_ptr` 宏。在我们创建一个`per-cpu`变量并对其修改后，我们必须调用 `put_cpu_var` 来启用抢占。因此，per-cpu 变量的典型用法如下：

```C
get_cpu_var(var);
...
//Do something with the 'var'
...
put_cpu_var(var);
```

`this_cpu_ptr` 宏在[include/linux/percpu-defs.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/percpu-defs.h#L253)中定义，如下：

```C
#define raw_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	arch_raw_cpu_ptr(ptr);						\
})

#define this_cpu_ptr(ptr) raw_cpu_ptr(ptr)
```

`this_cpu_ptr` 宏展开后调用 `raw_cpu_ptr` 宏，返回当前CPU的 `per-cpu` 变量。后者，首先调用了 `__verify_pcpu_ptr` 宏，该宏声明了`ptr` 类型的 `const void __percpu *`变量，然后访问这个变量，验证是否成功访问。如下：

```C
#define __verify_pcpu_ptr(ptr)
do {
	const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;
	(void)__vpp_verify;
} while (0)
```

在验证指针后，调用 `arch_raw_cpu_ptr`宏。该宏在[include/asm-generic/percpu.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/percpu.h#L43) 中定义，如下：

```C
#ifndef __my_cpu_offset
#define __my_cpu_offset per_cpu_offset(raw_smp_processor_id())
#endif

#ifndef arch_raw_cpu_ptr
#define arch_raw_cpu_ptr(ptr) SHIFT_PERCPU_PTR(ptr, __my_cpu_offset)
#endif
```

我们可以看到 `arch_raw_cpu_ptr` 宏展开后，是两个参数的 `SHIFT_PERCPU_PTR` 宏的调用。第一个参数是我们的指针，第二个参数是 `per_cpu_offset` 宏获取的偏移量。

```C
#ifndef __per_cpu_offset
extern unsigned long __per_cpu_offset[NR_CPUS];

#define per_cpu_offset(x) (__per_cpu_offset[x])
#endif
```

可以看到，`per_cpu_offset` 宏扩展为 `__per_cpu_offset` 数组的索引值。其中 `NR_CPUS`是 CPU 的数量，`__per_cpu_offset` 数组以 CPU 变量拷贝之间的距离填充。在前面设置 Per-CPU区域时进行了设置：

```C
per_cpu_offset(cpu) = delta + pcpu_unit_offsets[cpu];
```

接下来，让我们来看下 `SHIFT_PERCPU_PTR` 的实现：

```C
#define SHIFT_PERCPU_PTR(__p, __offset)					\
	RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset))
```

`RELOC_HIDE` 只是取得偏移量 `(typeof(ptr)) (__ptr + (off))`，并返回一个指向该变量的指针。

### 3.2 获取指定CPU的Per-CPU变量

`get_cpu_var`宏只能获取当前CPU上的 Per-CPU 变量，我们可以使用 `per_cpu_ptr` 宏获取指定CPU的变量。如下：

```C
#define per_cpu_ptr(ptr, cpu)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)));			\
})
```

可以看到，`per_cpu_ptr` 宏在调用 `__verify_pcpu_ptr` 验证变量指针后，调用 `SHIFT_PERCPU_PTR` 获取对应CPU的偏移量的指针。

## 4 结束语

在这一部分我们分析了Linux内核`Per-CPU`变量的实现过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
