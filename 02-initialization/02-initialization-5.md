
# Linux内核初始化 （第五部分）

## 0 内核剩余部分初始化

在上一篇中，Linux内核进行平台相关初始化，接下来，我们继续返回`start_kernel`函数，继续分析后续的初始化过程。

## 1 调度处理程序前初始化

### 1.1 设置命令行（`setup_command_line`）

`setup_command_line`函数传入内核命令行参数，并分配几个缓冲区来存储命令行。包括以下几个缓冲区：`saved_command_line`为引导命令行,`initcall_command_line`为`pre-initcall`参数解析命令行,`static_command_line`为参数解析的命令行。这些命令行调用`memblock_alloc`函数来分配。

### 1.2 CPU设置

* **获取CPU数量(`setup_nr_cpu_ids`)**

我们通过`setup_nr_cpu_ids`函数获取可设置的cpu数量。`setup_nr_cpu_ids`函数在[kernel/smp.c](https://github.com/torvalds/linux/blob/v5.4/kernel/smp.c#L572)中实现。如下：

```C
void __init setup_nr_cpu_ids(void)
{
	nr_cpu_ids = find_last_bit(cpumask_bits(cpu_possible_mask),NR_CPUS) + 1;
}
```

`nr_cpu_ids`变量表示CPU的数量，`NR_CPUS`表示在内核选项配置时设置的最大的CPU数量。实际上，我们需要调用这个函数，是因为`NR_CPUS`可能比实际的CPU数量要多。这里我们可以看到`find_last_bit`函数需要传入两个参数：`cpu_possible_mask`的比特数量和`NR_CPUS`。

在`setup_arch`函数中我们可以看到`prefill_possible_map`函数计算并填充所有可用的CPU到`cpu_possible_mask`中。我们调用`find_last_bit`函数根据mask地址和最大的数量来查找第一个设置位的位数。

* **获取pre-CPU区域(`setup_per_cpu_areas`)**

`setup_per_cpu_areas`函数设置per-CPU内存区域。`setup_per_cpu_areas`函数在[arch/x86/kernel/setup_percpu.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup_percpu.c#L168)中实现。

首先，根据`pcpu_chosen_fc`的设置，根据`pcpu_embed_first_chunk`或`pcpu_page_first_chunk`方式来分配第一个区块。`pcpu_chosen_fc`可通过`early_param("percpu_alloc", percpu_alloc_setup);`早期参数设置。

接下来，变量所有的CPU设置其信息，包括：this_cpu_off, cpu_number, segment, stack_canary等。

最后，设置cpumask和同步初始的页表。

* **SMP准备启动CPU(`smp_prepare_boot_cpu`)**

`smp_prepare_boot_cpu`函数在[arch/x86/include/asm/smp.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/smp.h#L80)中实现。仅仅调用`smp_ops.smp_prepare_boot_cpu();`函数。

`smp_ops`是一个`struct smp_ops`结构，在[arch/x86/kernel/smp.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/smp.c#L275)中定义，如下：

```C
struct smp_ops smp_ops = {
    smp_prepare_boot_cpu = native_smp_prepare_boot_cpu,
    ...
}
EXPORT_SYMBOL_GPL(smp_ops);
```

`native_smp_prepare_boot_cpu`函数在[arch/x86/kernel/smpboot.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/smpboot.c#L1388)中实现。如下：

```C
void __init native_smp_prepare_boot_cpu(void)
{
	int me = smp_processor_id();
	switch_to_new_gdt(me);
	/* already set me in cpu_online_mask in boot_cpu_init() */
	cpumask_set_cpu(me, cpu_callout_mask);
	cpu_set_state_online(me);
	native_pv_lock_init();
}
```

* **切换GDT(`switch_to_new_gdt`)**

执行过程如下：首先，调用`smp_processor_id`函数获取当前CPU的id；然后，根据获取的处理器id，我们调用`switch_to_new_gdt`函数重新加载[GDT(Global Descriptor Table)](https://en.wikipedia.org/wiki/Global_Descriptor_Table)，`switch_to_new_gdt`函数在[arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/common.c#L588)中实现，如下：

```C
void switch_to_new_gdt(int cpu)
{
	/* Load the original GDT */
	load_direct_gdt(cpu);
	/* Reload the per-cpu base */
	load_percpu_segment(cpu);
}

...
void load_direct_gdt(int cpu)
{
	struct desc_ptr gdt_descr;

	gdt_descr.address = (long)get_cpu_gdt_rw(cpu);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);
}

...
void load_percpu_segment(int cpu)
{
#ifdef CONFIG_X86_32
	loadsegment(fs, __KERNEL_PERCPU);
#else
	__loadsegment_simple(gs, 0);
	wrmsrl(MSR_GS_BASE, cpu_kernelmode_gs_base(cpu));
#endif
	load_stack_canary_segment();
}
```

`load_direct_gdt`函数直接加载`GDT`描述符，`gdt_descr`变量表示当前`GDT`描述符的指针，我们获取根给定的CPU获取`GDT`描述符的地址和大小。`GDT_SIZE`的大小是固定的，值为`128`或者`(GDT_ENTRIES*8)`；通过`get_cpu_gdt_rw`函数获取描述符的地址，如下：

```C
static inline struct desc_struct *get_cpu_gdt_rw(unsigned int cpu)
{
	return per_cpu(gdt_page, cpu).gdt;
}
```

`get_cpu_gdt_rw`函数使用`per_cpu`宏获取来获取给定CPU上的`gdt_page`perCPU变量。`gdt_page`perCPU变量在[arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head_64.S#L469)中定义，如下：

```bash
early_gdt_descr:
	.word	GDT_ENTRIES*8-1
early_gdt_descr_base:
	.quad	INIT_PER_CPU_VAR(gdt_page)
```

并且，我们在[arch/x86/kernel/vmlinux.lds.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/vmlinux.lds.S#L436)链接文件中，可以看到`gdt_page`perCPU变量位于`__per_cpu_load`符号后面，如下：

```bash
#define INIT_PER_CPU(x) init_per_cpu__##x = ABSOLUTE(x) + __per_cpu_load
INIT_PER_CPU(gdt_page);
INIT_PER_CPU(fixed_percpu_data);
INIT_PER_CPU(irq_stack_backing_store);
```

而，`gdt_page`在[arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/common.c#L114)中定义，如下：

```C
DEFINE_PER_CPU_PAGE_ALIGNED(struct gdt_page, gdt_page) = { .gdt = {
#ifdef CONFIG_X86_64
	[GDT_ENTRY_KERNEL32_CS]		= GDT_ENTRY_INIT(0xc09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(0xa09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(0xc093, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER32_CS]	= GDT_ENTRY_INIT(0xc0fb, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_DS]	= GDT_ENTRY_INIT(0xc0f3, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_CS]	= GDT_ENTRY_INIT(0xa0fb, 0, 0xfffff),
#else
...
```

在获取到`GDT`描述符的地址和大小后，调用`load_gdt`函数通过`lgdt`指令重新加载`GDT`。

在重新加载`gdt`描述符后，我们调用`load_percpu_segment`函数加载`percpu_segment`。`percpu`区域的基地址必须包括`gs`寄存器（或在`x86`平台为`fs`寄存器），因此，我们使用`gs`寄存器。接下来，我们写入`fixed_percpu_data`(`cpu_kernelmode_gs_base`函数的返回值)的基地址，并设置栈的[金丝雀（canary）](https://en.wikipedia.org/wiki/Buffer_overflow_protection)信息。

* **设置CPU状态**

在重新加载`GDT`后，我们填充当前CPU在`cpu_callout_mask`上的位图信息；并设置`cpu_hotplug_state`percpu变量为在线状态（`CPU_ONLINE`）；

在我们初始化引导处理器（即，第一个启动的处理器）后，其他的处理器在多核处理器系统中叫做辅助处理器(secondary processors)，在Linux内核中使用`cpu_callin_mask`和`cpu_callout_mask`变量。

在引导处理器初始化后，它会更新`cpu_callout_mask`以指示接下来可以初始化哪个辅助处理器。所有其他的辅助处理器在做同样的初始化工作之前需要检查引导处理器位上的`cpu_callout_mask`。只有在引导处理器用这个辅助处理器填充`cpu_callout_mask`之后，它才会继续其初始化的其余部分。在某个处理器完成其初始化过程之后，处理器填充 `cpu_callin_mask`。 一旦引导处理器在`cpu_callin_mask`中找到当前辅助处理器的位，该处理器就会重复相同的过程来初始化剩余的辅助处理器的一个。

* **初始化PV锁**

`native_pv_lock_init`函数在[arch/x86/kernel/paravirt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/paravirt.c#L110)中实现。如下：

```C
void __init native_pv_lock_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_HYPERVISOR))
		static_branch_disable(&virt_spin_lock_key);
}

DEFINE_STATIC_KEY_TRUE(virt_spin_lock_key);
```

`virt_spin_lock_key`是一个`static_key`，这里将其值设置为`disable`状态。

* **启动CPU热插拔初始化(`boot_cpu_hotplug_init`)**

`boot_cpu_hotplug_init`函数修改启动CPU的状态，将状态设置为启动状态。在[kernel/cpu.c](https://github.com/torvalds/linux/blob/v5.4/kernel/cpu.c#L2368)中实现，如下：

```C
void __init boot_cpu_hotplug_init(void)
{
#ifdef CONFIG_SMP
	cpumask_set_cpu(smp_processor_id(), &cpus_booted_once_mask);
#endif
	this_cpu_write(cpuhp_state.state, CPUHP_ONLINE);
}
```

### 1.3 建立区域列表(`build_all_zonelists`)

`build_all_zonelists`函数在[mm/page_alloc.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_alloc.c#L5820)。

该函数建立优先分配区域的顺序。什么是区域（zones）和顺序（order），我们很快会明白。首先，我们来看下Linux内核是如何看待物理内存的，物理内存被分成库（banks），称为节点（nodes）。如果你的硬件不支持NUMA，你将看到一个节点：

```bash
cat /sys/devices/system/node/node0/numastat 
numa_hit 4223144
numa_miss 0
numa_foreign 0
interleave_hit 102440
local_node 4223144
other_node 0
```

每一个`node`在Linux内核中使用`struct pglist_data`(或者`pg_data_t`)表示。每个节点都被划分成许多特殊大小的块，称为区域（zones）。每一个区域（zone）在Linux内核中使用`struct zone`表示。`struct pglist_data`和`struct zone`结构在[include/linux/mmzone.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/mmzone.h#L418)中定义。zone有以下类型，使用`enum zone_type`定义：

* ZONE_DMA - 0 ~ 16M的内存空间
* ZONE_DMA32 - 在32位设备下使用，只能使用4G以下内存空间作为DMA区域
* ZONE_NORMAL - 所有的内存空间
* ZONE_HIGHMEM - 在特殊的i386平台下使用
* ZONE_MOVABLE - 包含可移动页的区域
* ZONE_DEVICE - 包含设备的区域

我们可以通过以下方式获取区域：

```bash
cat /proc/zoneinfo 
Node 0, zone      DMA
  per-node stats
      nr_inactive_anon 40
    	...
Node 0, zone    DMA32
  pages free     758944
        min      6133
        ...
Node 0, zone   Normal
  pages free     223815
        min      10729
        ...
Node 0, zone  Movable
  pages free     0
        min      0
        ...
Node 0, zone   Device
  pages free     0
        min      0
        ...
```

`build_all_zonelists`函数调用`build_zonelists`函数建立一个有序的区域列表，当指定的区域或节点（zones/nodes）不能满足分配请求时，访问下一个区域或节点。

### 1.4 其他初始化过程

* **内存页分配初始化（`page_alloc_init`）**

在进入Linux内核调度器初始化程序前，我们还必须做一些事情。首先，我们调用`page_alloc_init`函数，在[mm/page_alloc.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_alloc.c#L7641)中实现。如下：

```C
void __init page_alloc_init(void)
{
	int ret;
#ifdef CONFIG_NUMA
	if (num_node_state(N_MEMORY) == 1)
		hashdist = 0;
#endif
	ret = cpuhp_setup_state_nocalls(CPUHP_PAGE_ALLOC_DEAD,
					"mm/page_alloc:dead", NULL,
					page_alloc_cpu_dead);
	WARN_ON(ret < 0);
}
```

该函数设置CPU热插拔状态中`CPUHP_PAGE_ALLOC_DEAD`的`startup`和`teardown`回调函数。

* **打印内核命令行**

在`dmsg`中可以找到如下信息：

```bash
[    0.439746] Kernel command line: nokaslr text root=/dev/vda5 rw console=ttyS0
```

* **跳转标签初始化（`jump_label_init`）**

接下来，我们调用`jump_label_init`函数，初始化跳转标签。在`setup_arch`函数中已经调用过。

* **解析早期参数**

`parse_early_param`函数和`parse_args`函数处理命令行参数。`parse_args`函数在[kernel/params.c](https://github.com/torvalds/linux/blob/v5.4/kernel/params.c#L161)中实现。

在`setup_arch`函数中我们已经调用了`parse_early_param`函数，现在为什么又调用一次？答案很简单，我们在`setup_arch`函数中进行平台相关设置（如：我们使用的平台`x86_64`），但并不是所有的平台都调用这个函数。

我们调用`parse_args`函数处理非早期命令行参数，如：`unknown_bootoption`函数处理未知的命令行参数，`set_init_arg`函数处理`init`参数。

* **设置日志缓冲区（`setup_log_buf`）**

接下来，我们调用`setup_log_buf`函数来设置`printk`日志缓冲区。我们在`setup_arch`函数中已经介绍过。

* **VFS缓存早期初始化（`vfs_caches_init_early`）**

`vfs_caches_init_early`函数初始化早期[虚拟文件系统（VFS，virtual file system）](http://en.wikipedia.org/wiki/Virtual_file_system)，在[fs/dcache.c](https://github.com/torvalds/linux/blob/v5.4/fs/dcache.c#L3193)中实现。如下：

```C
void __init vfs_caches_init_early(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(in_lookup_hashtable); i++)
		INIT_HLIST_BL_HEAD(&in_lookup_hashtable[i]);
	dcache_init_early();
	inode_init_early();
}
```

首先，初始化`in_lookup_hashtable`，`in_lookup_hashtable`变量是一个`struct hlist_bl_head`结构的数组，`struct hlist_bl_head`是一个双向链表的头节点。相关定义如下：

```C
#define IN_LOOKUP_SHIFT 10
static struct hlist_bl_head in_lookup_hashtable[1 << IN_LOOKUP_SHIFT];

struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next, **pprev;
};
```

`dcache_init_early`函数调用`alloc_large_system_hash`函数，如下:

```C
	dentry_hashtable =	alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_bl_head), dhash_entries, 13,
					HASH_EARLY | HASH_ZERO, &d_hash_shift,
					NULL, 0, 0);
```

`alloc_large_system_hash`函数分配一个大型系统的哈希表，在[mm/page_alloc.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_alloc.c#L8066)中实现。`dentry_hashtable`是一个`struct hlist_bl_head *`结构的指针。

`inode_init_early`函数实现和`dcache_init_early`函数类似，分配`Inode-cache`哈希表。

在`dmesg`中可以看到以下信息：

```bash
[    0.461238] Dentry cache hash table entries: 1048576 (order: 11, 8388608 bytes, linear)
[    0.472058] Inode-cache hash table entries: 524288 (order: 10, 4194304 bytes, linear)
```

* **排序内置的异常表（`sort_main_extable`）**

`sort_main_extable`函数在[kernel/extable.c](https://github.com/torvalds/linux/blob/v5.4/kernel/extable.c#L35)中实现，排序在`__start___ex_table`和`__stop___ex_table`之间内置的异常表。

* **初始化陷阱门（`trap_init`）**

`trap_init`函数设置陷阱门的中断处理程序，在[arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/traps.c#L925)中实现。设置IST、def_idts，ist_idts等中断处理程序。

* **初始化内存管理器（`mm_init`）**

`mm_init`函数设置内核内存管理器，在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L549)中实现。如下：

```C
static void __init mm_init(void)
{
	page_ext_init_flatmem();
	init_debug_pagealloc();
	report_meminit();
	mem_init();
	kmem_cache_init();
	kmemleak_init();
	pgtable_init();
	debug_objects_mem_init();
	vmalloc_init();
	ioremap_huge_init();
	init_espfix_bsp();
	pti_init();
}
```

`page_ext_init_flatmem`函数依赖`CONFIG_SPARSEMEM`配置选项，初始化扩展内存页。在[mm/page_ext.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_ext.c#L166)中实现。
`init_debug_pagealloc`函数依赖`CONFIG_DEBUG_PAGEALLOC`配置选项，初始化内存调试信息。在[mm/page_alloc.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_alloc.c#L720)中实现。
`report_meminit`函数打印内存自动初始化状态。
`mem_init`函数释放所有启动内存`bootmem`，在[arch/x86/mm/init_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/init_64.c#L1235)中实现。
`kmem_cache_init`函数初始化内核内存缓存，在[mm/slub.c](https://github.com/torvalds/linux/blob/v5.4/mm/slub.c#L4223)中实现。
`kmemleak_init`函数依赖`CONFIG_DEBUG_KMEMLEAK`配置选项，初始化内存泄漏检查信息。在[mm/kmemleak.c](https://github.com/torvalds/linux/blob/v5.4/mm/kmemleak.c#L1926)中实现。
`pgtable_init`函数初始化`page->ptl`和`pgd_cache`这两个内核缓存信息。
`debug_objects_mem_init`函数依赖`CONFIG_DEBUG_OBJECTS`配置选项，初始化调式对象内存。在[lib/debugobjects.c](https://github.com/torvalds/linux/blob/v5.4/lib/debugobjects.c#L1349)中实现。
`vmalloc_init`函数初始化`vma`相关设置，包括：初始化`vmap_area`内核缓存；percpu上的`vmap_block_queue`和`vfree_deferred`；导入已存在的vmlist。在[mm/vmalloc.c](https://github.com/torvalds/linux/blob/v5.4/mm/vmalloc.c#L1900)中实现。
`ioremap_huge_init`函数依赖`CONFIG_HAVE_ARCH_HUGE_VMAP`配置选项，初始化iomap大页支持能力。在[lib/ioremap.c](https://github.com/torvalds/linux/blob/v5.4/lib/ioremap.c#L30)中实现。
`init_espfix_bsp`函数依赖`CONFIG_X86_ESPFIX64`配置选项，初始化中断处理程序的`ministacks`。在[arch/x86/kernel/espfix_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/espfix_64.c#L114)中实现。
`pti_init`函数依赖`CONFIG_PAGE_TABLE_ISOLATION`配置选项，初始化内核页表隔离(page table isolation)。在[arch/x86/mm/pti.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/pti.c#L623)中实现。

* **早期追踪初始化（`early_trace_init`）**

`early_trace_init`函数初始化追踪信息，在[kernel/trace/trace.c](https://github.com/torvalds/linux/blob/v5.4/kernel/trace/trace.c#L9203)中实现。设置寄存器、函数等追踪信息。

## 2 调度处理程序初始化（`sched_init`）

`sched_init`函数初始化调度处理程序，在[kernel/sched/core.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/core.c#L6557)中实现。

### 2.1 等待队列初始化（`wait_bit_init`）

进入调度处理程序初始化后，第一个调用的函数是`wait_bit_init`，在[kernel/sched/wait_bit.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/wait_bit.c#L244)中实现。其实现非常简单，初始化等待队列，如下：

```C
void __init wait_bit_init(void)
{
	int i;
	for (i = 0; i < WAIT_TABLE_SIZE; i++)
		init_waitqueue_head(bit_wait_table + i);
}

#define WAIT_TABLE_BITS 8
#define WAIT_TABLE_SIZE (1 << WAIT_TABLE_BITS)
static wait_queue_head_t bit_wait_table[WAIT_TABLE_SIZE] __cacheline_aligned;
```

`bit_wait_table`是一个等待队列的数组，用于等待/唤醒指定的等待队列。

### 2.2 初始化`root_task_group`

接下来，我们初始化`root_task_group`信息，如下：

```C
#ifdef CONFIG_FAIR_GROUP_SCHED
	ptr += 2 * nr_cpu_ids * sizeof(void **);
#endif
#ifdef CONFIG_RT_GROUP_SCHED
	ptr += 2 * nr_cpu_ids * sizeof(void **);
#endif
	if (ptr) {
		ptr = (unsigned long)kzalloc(ptr, GFP_NOWAIT);
#ifdef CONFIG_FAIR_GROUP_SCHED
		root_task_group.se = (struct sched_entity **)ptr;
		ptr += nr_cpu_ids * sizeof(void **);
		root_task_group.cfs_rq = (struct cfs_rq **)ptr;
		ptr += nr_cpu_ids * sizeof(void **);
#endif /* CONFIG_FAIR_GROUP_SCHED */
#ifdef CONFIG_RT_GROUP_SCHED
		root_task_group.rt_se = (struct sched_rt_entity **)ptr;
		ptr += nr_cpu_ids * sizeof(void **);
		root_task_group.rt_rq = (struct rt_rq **)ptr;
		ptr += nr_cpu_ids * sizeof(void **);
#endif /* CONFIG_RT_GROUP_SCHED */
	}
```

可以看到，`ptr`的大小取决于`CONFIG_FAIR_GROUP_SCHED`和`CONFIG_RT_GROUP_SCHED`这两个内核配置选项。这两个选项提供了两种不同的调度计划模型，公平分组调度和[实时分组调度（RT，real time）](https://github.com/torvalds/linux/blob/v5.4/Documentation/scheduler/sched-rt-group.rst)。

通常，调度程序对单个任务进行操作，并努力为每个任务提供公平的CPU时间。有时，可能需要对任务进行分组并为每个这样的任务组提供公平的CPU时间。例如，可能希望首先为系统上的每个用户提供公平的CPU时间，然后再为属于用户的每个任务提供公平的CPU时间。`CONFIG_CGROUP_SCHED`配置选项允许对任务进行分组，并在这些组之间公平地分配CPU时间。`CONFIG_RT_GROUP_SCHED`允许对实时（即，`SCHED_FIFO`和`SCHED_RR`）任务进行分组。`CONFIG_FAIR_GROUP_SCHED`允许对`CFS`（即`SCHED_NORMAL`和`SCHED_BATCH`）任务进行分组。

目前Linux的调度程序的设计方式使用了`调度类（scheduler classes）`的方式，是一种可扩展的调度程序模块层次结构。这些模块封装了调度策略细节，并由调度器核心处理，而不用过多的了解核心代码。Linux中使用的调度类有`stop_sched_class`, `dl_sched_class`, `rt_sched_class`, `fair_sched_class`, `idle_sched_class`等五种调度类。

Linux常用的调度处理程序是[完全公平调度（CFS，Completely Fair Scheduler）](https://github.com/torvalds/linux/blob/v5.4/Documentation/scheduler/sched-design-CFS.rst)，在[kernel/sched/fair.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/fair.c#L10427)中实现。CFS通过使用虚拟时间（`vruntime`）在真实的硬件上建模了一个理想的、精确的多任务CPU，在理想的CPU上每个任务都可以获取`1/n`的处理时间（`n`表示运行的任务数量）。CFS实现了三种调度策略：

* `SCHED_NORMAL`（传统上称为`SCHED_OTHER`）：用于常规任务的调度策略，每个任务占用的CPU通过[nice](http://en.wikipedia.org/wiki/Nice_(Unix))值决定的。
* `SCHED_BATCH`：不会像常规任务那样频繁地抢占CPU，从而允许任务运行更长时间并更好地利用缓存。批处理作业适用于非交互性任务。
* `SCHED_IDLE`：它不是一个真正的空闲计时器调度程序，适用于除了当前任务没有其他任务运行时，以避免优先级反转导致死锁。

对时间要求严格的应用程序使用实时调度，在[kernel/sched/rt.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/rt.c#L2357)中实现，支持`SCHED_FIFO`和`SCHED_PR`调度策略。空闲程序的调度类，在[kernel/sched/idle.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/idle.c#L455)中实现。基于截至时间的调度类，在[kernel/sched/deadline.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/deadline.c#L2431)中实现，支持`SCHED_DEADLINE`调度策略。

尽管系统最小的调度单元是进程，但Linux内核调度程序并不使用`task_struct`结构作为调度单元，而是使用一个`sched_entity`特殊的结构。我们可以看到`ptr += 2 * nr_cpu_ids * sizeof(void **);`计算调度程序所需的内存大小，CPU的数量乘以指针的大小后再乘以2。乘以2是因为我们需要为调度实体结构（scheduler entity）和运行队列（runqueue）这两个变量分配空间。在计算大小后，我们调用`kzalloc`函数分配内存空间，并且设置`sched_entity`和`runquques`的指针。

Linux组调度机制允许指定层次结构，这种层次结构的根是一个叫`root_task_group`的任务组结构。这个结构包括了许多字段，现在我们只关心`se`, `cfs_rq`, `rt_se`, `rt_rq`这个四个变量。`struct task_group`在[kernel/sched/sched.h](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/sched.h#L355)中定义，如下：

```C
struct task_group {
#ifdef CONFIG_FAIR_GROUP_SCHED
    struct sched_entity **se;
    struct cfs_rq       **cfs_rq;
    ...
#endif
#ifdef CONFIG_RT_GROUP_SCHED
    struct sched_rt_entity  **rt_se;
    struct rt_rq            **rt_rq;
    ...
#endif
    ...
}
```

`se`和`rt_se`变量是`sched_entity`结构的实例， `cfs_rq`和`rt_rq`表示运行队列。运行队列（`run queue`）是一个特殊的`per-cpu`结构，是Linux内核调度程序用于存放活动的（`active`）的线程，即，调度程序可用来调度运行的线程组。

### 2.3 初始化任务带宽

接下来，初始化实时任务（`real time`）和截止时间任务（`deadline`）的CPU带宽时间，如下：

```C
    init_rt_bandwidth(&def_rt_bandwidth, global_rt_period(), global_rt_runtime());
    init_dl_bandwidth(&def_dl_bandwidth, global_rt_period(), global_rt_runtime());
```

这两个任务组都依赖于CPU时间。`def_rt_bandwidth`和`def_dl_bandwidth`这两个结构表示实时任务和截止时间任务的默认带宽值。目前，我们暂时不关注这两个结构的定义，只关注`sched_rt_period_us`和`sched_rt_runtime_us`这两个变量的值。`sched_rt_period_us`表示CPU调度的时间周期，`sched_rt_runtime_us`表示在一个周期时间内分配个实时任务的时间量。可以在系统设置里看到：

```bash
$ cat /proc/sys/kernel/sched_rt_period_us 
1000000

$ cat /proc/sys/kernel/sched_rt_runtime_us 
950000
```

任务组的这两个相关参数配置在`<cgroup>/cpu.rt_period_us`和`<cgroup>/cpu.rt_runtime_us`中设置。由于现在还没有加载文件系统，`def_rt_bandwidth`和`def_dl_bandwidth`使用`global_rt_period`和`global_rt_runtime`函数返回的默认值进行初始化。

### 2.4 初始化根域（root domain）
  
在开启`CONFIG_SMP`配置选项的情况下，调用`init_defrootdomain`函数初始化根域。`init_defrootdomain`函数在[kernel/sched/topology.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/topology.c#L535)中实现。如下：

```C
#ifdef CONFIG_SMP
	init_defrootdomain();
#endif
```

实时调度处理程序需要全局资源来做调度决策，但随着CPU数量的增加出现了扩展性的瓶颈。为了避免提升扩展性带来的瓶颈，引入了根域（root domain）的概念。调度处理程序不是绕过所有的运行队列，而是获取CPU信息，从`root_domain`结构中推/拉实时任务。该结构在[kernel/sched/sched.h](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/sched.h#L732)中定义，仅追踪可用于推送或拉取进程的CPU。

### 2.4 初始化实时任务带宽

接下来，初始化`root_task_group`中实时任务的带宽。如下：

```C
#ifdef CONFIG_RT_GROUP_SCHED
    init_rt_bandwidth(&root_task_group.rt_bandwidth,
            global_rt_period(), global_rt_runtime());
#endif
```

### 2.5 初始化任务组

接下来，根据`CONFIG_CGROUP_SCHED`的内核配置选项，我们分配任务组的缓存；初始化`root_task_group`中的`children`和`siblings`列表；最后初始化主动程序组调度。如下：

```C
#ifdef CONFIG_CGROUP_SCHED
    task_group_cache = KMEM_CACHE(task_group, 0);

    list_add(&root_task_group.list, &task_groups);
    INIT_LIST_HEAD(&root_task_group.children);
    INIT_LIST_HEAD(&root_task_group.siblings);
    autogroup_init(&init_task);
#endif /* CONFIG_CGROUP_SCHED */
```

### 2.6 初始化可用CPU的运行队列

接下来，我们遍历所有可用的CPU，并初始化每个CPU的运行队列。如下：

```C
    for_each_possible_cpu(i) {
        struct rq *rq;
        rq = cpu_rq(i);
        ...
    }
```

`rq`结构在[kernel/sched/sched.h](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/sched.h#L847)中定义，是调度程序中基础的数据结构。调度程序通过运行队列来决定下一个运行的程序。

### 2.7 设置初始任务的负载权重（`set_load_weight`）

`set_load_weight`函数在[kernel/sched/core.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/core.c#L747)实现。

首先，我们需要明白什么是一个程序负载权重（load weight）。通过查看`sched_entity`结构的定义，我们可以看到`load`字段，它表示一个`load_weight`的结构。`load_weight`结构仅包含两个字段，实际的负载权重和固定的值。如下：

```C
struct sched_entity {
	struct load_weight		load;
	...
};

struct load_weight {
	unsigned long			weight;
	u32				inv_weight;
};
```

在系统中的每个进程都有一个优先级（priority），高优先级的程序允许获取更多的运行时间。进程的负载权重是程序的优先级和时间片的转换关系。每个进程有下面几个关于优先级的字段：

```C
struct task_struct {
	...
	int				prio;
	int				static_prio;
	int				normal_prio;
	unsigned int			rt_priority;
	...
};
```

`prio`字段是个动态的优先级，但在进程的生命周期里不能根据其静态优先级和进程的交互性进行更改。`static_prio`字段包含初始的优先级，或者熟知的`nice`值，这个值除用户修改外不会被内核修改。`normal_prio`字段基于`static_prio`的值，随着调度策略的变更而改变。

`set_load_weight`函数设置`init_task`结构中的`load_weight`字段。如下：

```C
static void set_load_weight(struct task_struct *p, bool update_load)
{
	int prio = p->static_prio - MAX_RT_PRIO;
	struct load_weight *load = &p->se.load;
	if (task_has_idle_policy(p)) {
		load->weight = scale_load(WEIGHT_IDLEPRIO);
		load->inv_weight = WMULT_IDLEPRIO;
		p->se.runnable_weight = load->weight;
		return;
	}
	if (update_load && p->sched_class == &fair_sched_class) {
		reweight_task(p, prio);
	} else {
		load->weight = scale_load(sched_prio_to_weight[prio]);
		load->inv_weight = sched_prio_to_wmult[prio];
		p->se.runnable_weight = load->weight;
	}
}
```

可以看到，首先根据`static_prio`计算初始`prio`，通过`sched_prio_to_weight`和`sched_prio_to_wmult`数组来设置`weight`和`inv_weight`的值，这两个数组包含优先级到负载权重的转换。如果是`idle`进程，我们设置最小的负载权重。

### 2.8 内存和状态设置

* **MMU设置**

`mmgrab`函数增加`init_mm`的引用计数，在[include/linux/sched/mm.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/sched/mm.h#L34)中实现.

`enter_lazy_tlb`根据`mm_struct`设置TLB的状态，在[arch/x86/mm/tlb.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/tlb.c#L461)中实现。其中`current`是个宏定义，用来获取当前CPU上运行的任务信息。

* **设置当前任务为idle**

`init_idle`函数设置当前任务任务处于`idle`状态。在[kernel/sched/core.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/core.c#L6017)中实现。

* **计算下次调度时间**

计算下一次调度的时间`calc_load_update`的值，`calc_load_update = jiffies + LOAD_FREQ;`

### 2.9 初始化CFS调度类

`idle_thread_set_boot_cpu`函数设置当前CPU的idle进程为当前任务。在[kernel/smpboot.c](https://github.com/torvalds/linux/blob/v5.4/kernel/smpboot.c#L40)中实现。

`init_sched_fair_class`函数通过软中断来执行CFS调度，在[kernel/sched/fair.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/fair.c#L10508)实现。如下:

```C
__init void init_sched_fair_class(void)
{
#ifdef CONFIG_SMP
	open_softirq(SCHED_SOFTIRQ, run_rebalance_domains);

#ifdef CONFIG_NO_HZ_COMMON
...
#endif
#endif /* SMP */
}
```

通过注册软中断（sof irq）来调用`run_rebalance_domains`处理程序。在`SCHED_SOFTIRQ`触发后，将调用`run_rebalance_domains`函数来重新均衡当前CPU的运行队列。

### 2.10 初始化统计信息

`init_schedstats`函数初始化调度统计信息，在[kernel/sched/core.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/core.c#L2806)中实现。

`psi_init`函数初始化[PSI(Pressure Stall Information)](https://github.com/torvalds/linux/blob/v5.4/Documentation/accounting/psi.rst)，在[kernel/sched/psi.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/psi.c#L204)中实现。

`init_uclamp`函数在[kernel/sched/core.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/core.c#L1246)中实现。

### 2.11 设置调度器标签
  
在完成上面的工作后，我们完成了调度的初始化。现在修改`scheduler_running`变量。如下：

```C
scheduler_running = 1;
```

## 3 RCU初始化

### 3.1 禁用抢占和中断

接下来，我们可以看到和抢占相关的两个宏定义，`preempt_disable`和`preempt_enable`。抢占（`preempt`）是操作系统内核抢占当前任务以运行具有更高优先级任务的能力。在这里我们需要禁用抢占，是因为我们在早期启动期间只有一个`init`进程，我们在调用`cpu_idle()`函数前，整个调度过程很容易出错。

`preempt_disable`宏定义在[include/linux/preempt.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/preempt.h#L207)中定义，根据`CONFIG_PREEMPT_COUNT`的内核配置选项开启与否而不同，在`CONFIG_PREEMPT_COUNT`开启的情况下，定义如下：

```C
#define preempt_disable() \
do { \
	preempt_count_inc(); \
	barrier(); \
} while (0)
```

在`CONFIG_PREEMPT_COUNT`内核配置选项没有开启的情况下，定义如下：

```C
#define preempt_disable()			barrier()
```

我们可以看到，在使用`CONFIG_PREEMPT_COUNT`内核配置选项时，包含了`preempt_count_inc`的函数调用。`__preempt_count`的percpu变量存储抢占的数量。定义为`DECLARE_PER_CPU(int, __preempt_count);`，可用通过`preempt_count`函数返回`__preempt_count`的值。

在`preempt_disable`的第一个实现中通过`preempt_count_inc`增加`__preempt_count`的计数。`preempt_count_inc`宏定义如下：

```C
#define preempt_count_inc() preempt_count_add(1)
#define preempt_count_add(val)	__preempt_count_add(val)
```

`__preempt_count_add`函数调用`raw_cpu_add_4`宏定义增加指定的percpu变量，当前我们增加的变量是`__preempt_count`。在增加`__preempt_count`后，我们调用`barrier`宏，`barrier`宏展开后是优化的屏障，如下：

```C
#define barrier() __asm__ __volatile__("": : :"memory")
```

在`x86_64`架构平台下处理器访问独立内存操作可以优化为任何顺序。这就是我们需要时机来指出编译器和处理器的编译顺序，这种机制就是内存屏障。比如下面简单的代码：

```C
preempt_disable();
foo();
preempt_enable();
```

编译器在编译后可能为：

```C
preempt_disable();
preempt_enable();
foo();
```

在这种情况下，非抢占函数`foo`可能会被抢占。在我们将`barrier`宏放入`preempt_disable`和`preempt_enable`宏定义中，它阻止了`preempt_count_inc`与其他语句交互。关于`barrier`的更多信息，可以参考[Memory barrier](https://en.wikipedia.org/wiki/Memory_barrier)和[Documentation/memory-barriers.txt](https://github.com/torvalds/linux/blob/v5.4/Documentation/memory-barriers.txt)。

接下来，我们检查IRQ状态，在启用的状态下禁用本地中断（`x86_64`系统下通过`cli`指令）。如下：

```C
if (WARN(!irqs_disabled(), 
	"Interrupts were enabled *very* early, fixing it\n"))
	local_irq_disable();
```

### 3.2 RCU初始化（`rcu_init`）

* **RCU介绍**

接下来，调用`rcu_init`函数来初始化[RCU，Read-copy-update](https://en.wikipedia.org/wiki/Read-copy-update)。`rcu_init`的实现取决于`CONFIG_TINY_RCU`和`CONFIG_TREE_RCU`内核配置选项。第一种情况下`rcu_init`在[kernel/rcu/tiny.c](https://github.com/torvalds/linux/blob/v5.4/kernel/rcu/tiny.c#L153)；第二种情况下在[kernel/rcu/tree.c](https://github.com/torvalds/linux/blob/v5.4/kernel/rcu/tree.c#L3521)中实现。

RCU是Linux内核中实现的一种可扩展的高性能同步机制。在早期Linux内核为并发运行的应用程序提供了环境和支持，但是所有的执行都是在Linux内核中使用单个全局的锁进行同步的。在我们的时代，Linux内核没有单一的全局锁，而是提供了不同的同步机制，包括：无锁数据结构、percpu数据结构等。其中的一种机制是RCU。RCU为很少修改的数据而设计的，RCU的设计想法很简单，例如，有一个很少修改的数据结构，如果有人想改变这个数据结构，我们复制这个数据结构并在副本中进行所有更改。同时，该数据结构的所有其他用户都使用它的旧版本。接下来，我们需要选择原始版本没有用户使用时的安全时刻，使用修改后的副本对其进行更新。

当然，对RCU的描述非常简单。要了解RCU的一些细节，首先我们需要学习一些术语。RCU中的数据读着在临界区执行，每次数据读者到达临界区时，它都会调用`rcu_read_lock`，并在退出临界区时调用`rcu_read_unlock`。如果线程不在临界区，此时处于静止状态（`quiescent state`）。每个线程都处于静止状态的时刻称为 - 宽限期（`grace period`）。如果一个线程想要从数据结构中删除一个元素，这将分两步进行。第一步是删除，即原子性的从数据结构中删除元素，但不释放物理内存。在这个线程写者占用并等待写完成之后，从这一刻起，线程读者可以使用已删除的元素。宽限期结束后，将开始第二步删除元素，它只是从物理内存中删除元素。

有多种RCU的实现方式，旧的实现方式叫做经典实现，新的实现叫做`tree` RCU。接下来，让我们来看下`rcu_init`在[kernel/rcu/tree.c](https://github.com/torvalds/linux/blob/v5.4/kernel/rcu/tree.c#L3521)中实现。如下：

```C
void __init rcu_init(void)
{
	int cpu;
	rcu_early_boot_tests();
	rcu_bootup_announce();
	rcu_init_geometry();
	rcu_init_one();
	if (dump_tree)
		rcu_dump_rcu_node_tree();
	if (use_softirq)
		open_softirq(RCU_SOFTIRQ, rcu_core_si);

	pm_notifier(rcu_pm_notify, 0);
	for_each_online_cpu(cpu) {
		rcutree_prepare_cpu(cpu);
		rcu_cpu_starting(cpu);
		rcutree_online_cpu(cpu);
	}
	rcu_gp_wq = alloc_workqueue("rcu_gp", WQ_MEM_RECLAIM, 0);
	WARN_ON(!rcu_gp_wq);
	rcu_par_gp_wq = alloc_workqueue("rcu_par_gp", WQ_MEM_RECLAIM, 0);
	WARN_ON(!rcu_par_gp_wq);
	srcu_init();
}
```

`rcu_early_boot_tests`函数进行RCU自检。
`rcu_bootup_announce`函数及其调用的子函数，通过调用`pr_info`函数打印RCU根据内核配置参数生成的配置信息，如:`CONFIG_RCU_TRACE`, `CONFIG_RCU_FAST_NO_HZ`等等。

* **初始化层级结构（`rcu_init_geometry`）**

`rcu_init_geometry`函数在同一个文件中实现，根据CPU的数量计算树节点的几何分布。RCU提供`rcu_state`结构展现RCU全局状态和节点层次结构。层次结构通过`node`和`level`两个变量表示：

```C
struct rcu_state {
	struct rcu_node node[NUM_RCU_NODES];	/* Hierarchy. */
	struct rcu_node *level[RCU_NUM_LVLS + 1];
	...
};
```

`struct rcu_node`结构在[kernel/rcu/tree.h](https://github.com/torvalds/linux/blob/v5.4/kernel/rcu/tree.h#L41)中定义，包括了当前宽限期的信息，宽限期完成与否，是否切换到其他的CPU信息等。每个`rcu_node`节点包括了一组CPU的锁，这些`rcu_node`节点在`rcu_state`结构中是一个线性数组，以第一个节点为根元素展示树形结构。树形层次的根节点（第一层）是`node[0]`，`node[0]`被`level[0]`引用；第二层的节点是`node[1]`到`node[m]`，`node[1]`被`level[1]`引用；第三层从`node[m+1]`开始，`node[m+1]`被`level[2]`引用。层级的数量通过CPU的数量和`CONFIG_RCU_FANOUT`决定的。`NUM_RCU_NODES`表示RCU节点的数量，`RCU_NUM_LVLS`表示RCU层级的数量。这两个值依赖于CPU的数量，以`3`个层级为例：

```C
...
#elif NR_CPUS <= RCU_FANOUT_3
#  define RCU_NUM_LVLS	      3
#  define NUM_RCU_LVL_0	      1
#  define NUM_RCU_LVL_1	      DIV_ROUND_UP(NR_CPUS, RCU_FANOUT_2)
#  define NUM_RCU_LVL_2	      DIV_ROUND_UP(NR_CPUS, RCU_FANOUT_1)
#  define NUM_RCU_NODES	      (NUM_RCU_LVL_0 + NUM_RCU_LVL_1 + NUM_RCU_LVL_2)
#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0, NUM_RCU_LVL_1, NUM_RCU_LVL_2 }
#  define RCU_NODE_NAME_INIT  { "rcu_node_0", "rcu_node_1", "rcu_node_2" }
#  define RCU_FQS_NAME_INIT   { "rcu_node_fqs_0", "rcu_node_fqs_1", "rcu_node_fqs_2" }
#elif NR_CPUS <= RCU_FANOUT_4
...
```

以一个最简单的例子，在有8个CPU，每个`rcu_node`包括两个CPU的情况，整个层次结构如下：

```text
+-----------------------------------------------------------+
|  rcu_state                                                |
|               +---------------------------+               |
|               |          node[0]          |               |
|               +---------------------------+               |
|               |                           |               |
|        +------v------+             +------v------+        |
|        |   node[1]   |             |   node[2]   |        |
|        +-------------+             +-------------+        |
|        |             |             |             |        |
|   +----v----+   +----v----+   +----v----+   +----v----+   |
|   | node[3] |   | node[4] |   | node[5] |   | node[6] |   |
|   +---------+   +---------+   +---------+   +---------+   |
|        |             |             |               |      |
+--------|-------------|-------------|---------------|------+
         |             |             |               |
+--------v-------------v-------------v---------------v------+
|     CPU1     |     CPU3     |     CPU5     |     CPU7     |
|     CPU2     |     CPU4     |     CPU6     |     CPU8     |
+-----------------------------------------------------------+
```

`rcu_init_geometry`函数首先计算第一次和下次`fqs`（force-quiescent-state）的`jiffies`，即：初始化`jiffies_till_first_fqs`和`jiffies_till_next_fqs`变量；检查`rcu_fanout_leaf`是否变更，在变更的情况下进行调整进行调整；并在层级数量不够的情况下，重新调整层次。

* **初始化节点信息（`rcu_init_one`）**

`rcu_init_one`函数初始`rcu_state`结构信息，并初始化每个`rcu_node`节点信息。

* **初始化RCU软中断（`open_softirq`）**

在使用`use_softirq`的情况项，开启RCU软中断。执行函数`open_softirq(RCU_SOFTIRQ, rcu_core_si);`开启软中断。

* **在线CPU初始化RCU信息**

接下来，执行`pm_notifier(rcu_pm_notify, 0)`函数向注册CPU通知信息；并初始化所有在线CPU的RCU信息。如下：

```C
	pm_notifier(rcu_pm_notify, 0);
	for_each_online_cpu(cpu) {
		rcutree_prepare_cpu(cpu);
		rcu_cpu_starting(cpu);
		rcutree_online_cpu(cpu);
	}
```

* **创建工作队列**

接下来，创建`rcu_gp`和`rcu_par_gp`的加速工作队列；并调用`srcu_init`函数初始化`srcu`。

## 4 进程初始化

### 4.1 进程初始化前的部分

`radix_tree_init`函数初始化[Radix tree](http://en.wikipedia.org/wiki/Radix_tree)，创建`radix_tree_node`内核缓存和设置CPU的`CPUHP_RADIX_DEAD`状态回调函数。在[lib/radix-tree.c](https://github.com/torvalds/linux/blob/v5.4/lib/radix-tree.c#L1603)中实现。
`housekeeping_init`函数初始化`housekeeping`，在[kernel/sched/isolation.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/isolation.c#L66)中实现。
`workqueue_init_early`函数初始化早期运行队列子系统，在[kernel/workqueue.c](https://github.com/torvalds/linux/blob/v5.4/kernel/workqueue.c#L5866)中实现。
`trace_init`函数初始化追踪事件，在[kernel/trace/trace.c](https://github.com/torvalds/linux/blob/v5.4/kernel/trace/trace.c#L9216)。
`early_irq_init`函数初始化早期IRQ，在[kernel/irq/irqdesc.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/irqdesc.c#L519)中实现。
`init_IRQ`函数初始化percpu的中断向量，在[arch/x86/kernel/irqinit.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/irqinit.c#L79)中实现。
`init_timers`函数初始化定时器信息，并开启`TIMER_SOFTIRQ`的软中断。在[kernel/time/timer.c](https://github.com/torvalds/linux/blob/v5.4/kernel/time/timer.c#L2033)中实现。
`hrtimers_init`函数初始化高精度定时器信息，并开启`HRTIMER_SOFTIRQ`的软中断。在[kernel/time/hrtimer.c](https://github.com/torvalds/linux/blob/v5.4/kernel/time/hrtimer.c#L2086)中实现。
`softirq_init`函数初始化`tasklet`，并开启`TASKLET_SOFTIRQ`和`HI_SOFTIRQ`的软中断。在[kernel/softirq.c](https://github.com/torvalds/linux/blob/v5.4/kernel/softirq.c#L575)中实现。
`timekeeping_init`函数初始化时钟信息，在[kernel/time/timekeeping.c](https://github.com/torvalds/linux/blob/v5.4/kernel/time/timekeeping.c#L1532)中实现。
`perf_event_init`函数初始化perf事件，在[kernel/events/core.c](https://github.com/torvalds/linux/blob/v5.4/kernel/events/core.c#L12209)中实现。
`profile_init`函数初始化profile信息，在[kernel/profile.c](https://github.com/torvalds/linux/blob/v5.4/kernel/profile.c#L103)中实现。
`call_function_init`函数初始化调用函数信息，在[kernel/smp.c](https://github.com/torvalds/linux/blob/v5.4/kernel/smp.c#L90)中实现。
`local_irq_enable`函数启用本地IRQ中断，展开后最终执行`sti`指令，在[include/linux/irqflags.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irqflags.h#L140)中实现。
`console_init`函数初始化控制台信息，在[kernel/printk/printk.c](https://github.com/torvalds/linux/blob/v5.4/kernel/printk/printk.c#L2866)中实现。
`lockdep_init`函数依赖于`CONFIG_LOCKDEP`内核配置选项，打印[锁依赖验证器(locking dependency validator)](https://github.com/torvalds/linux/blob/v5.4/Documentation/locking/lockdep-design.rst)中实现。
`setup_per_cpu_pageset`函数分配并初始化percpu页，在[mm/page_alloc.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_alloc.c#L6181)中实现。
`numa_policy_init`函数初始化NUMA策略信息，在[mm/mempolicy.c](https://github.com/torvalds/linux/blob/v5.4/mm/mempolicy.c#L2709)中实现。
`acpi_early_init`函数初始化ACPI，并填充ACPI命名空间，在[drivers/acpi/bus.c](https://github.com/torvalds/linux/blob/v5.4/drivers/acpi/bus.c#L1018)中实现。
`sched_clock_init`函数设置调度处理程序时间，在[kernel/sched/clock.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sched/clock.c#L207)中实现。
`calibrate_delay`函数校准CPU延时，在[init/calibrate.c](https://github.com/torvalds/linux/blob/v5.4/init/calibrate.c#L275)中实现。
`pid_idr_init`函数初始`进程ID（PID）`进程空间目录，在[kernel/pid.c](https://github.com/torvalds/linux/blob/v5.4/kernel/pid.c#L524)中实现。
`anon_vma_init`函数创建`anon_vma`内核缓存，供匿名的虚拟内存区域使用，在[mm/rmap.c](https://github.com/torvalds/linux/blob/v5.4/mm/rmap.c#L433)中实现。
`thread_stack_cache_init`函数根据`THREAD_SIZE`和`PAGE_SIZE`两者的大小有不同的实现，当`THREAD_SIZE >= PAGE_SIZE`时，为空函数；否则，创建`thread_stack`内核缓存，在[kernel/fork.c](https://github.com/torvalds/linux/blob/v5.4/kernel/fork.c#L316)中实现。
`cred_init`函数创建`cred_jar`缓存，供凭证信息使用，在[kernel/cred.c](https://github.com/torvalds/linux/blob/v5.4/kernel/cred.c#L656)中实现。关于凭证的信息可以参考[Documentation/security/credentials.rst](https://github.com/torvalds/linux/blob/v5.4/Documentation/security/credentials.rst)。

### 4.2 进程初始化（`fork_init`）

`fork_init`函数进行`fork`相关初始化，在[kernel/fork.c](https://github.com/torvalds/linux/blob/v5.4/kernel/fork.c#L800)中实现。

* **分配`task_struct`缓存**

首先，`fork_init`函数分配`task_struct`缓存，是否分配依赖于`CONFIG_ARCH_TASK_STRUCT_ALLOCATOR`内核配置选项，如下：

```C
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR
#ifndef ARCH_MIN_TASKALIGN
#define ARCH_MIN_TASKALIGN	0
#endif
	int align = max_t(int, L1_CACHE_BYTES, ARCH_MIN_TASKALIGN);
	unsigned long useroffset, usersize;
	task_struct_whitelist(&useroffset, &usersize);
	task_struct_cachep = kmem_cache_create_usercopy("task_struct",
			arch_task_struct_size, align,
			SLAB_PANIC|SLAB_ACCOUNT,
			useroffset, usersize, NULL);
#endif
```

* **平台相关`task_struct`缓存初始化**

调用`arch_task_cache_init`函数初始化平台相关`task`缓存。在[arch/sh/kernel/process.c](https://github.com/torvalds/linux/blob/v5.4/arch/sh/kernel/process.c#L55)中实现。

* **最大线程数设置**

首先，调用`set_max_threads(MAX_THREADS);`函数设置最大线程数。默认的最大线程数为：

```C
#define FUTEX_TID_MASK		0x3fffffff
#define MAX_THREADS FUTEX_TID_MASK
```

接下来，初始化`init_task.signal`的资源限制，如下：

```C
	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;
	init_task.signal->rlim[RLIMIT_SIGPENDING] =
		init_task.signal->rlim[RLIMIT_NPROC];
```

`init_task.signal`字段表示信号处理器，是个`struct signal_struct`结构。`rlim[RLIMIT_NPROC]`是一个`struct rlimit`结构，表示资源限制情况。`struct rlimit`包含当前使用量和最大使用量两个字段。`RLIMIT_NPROC`表示进程使用的线程数量，`RLIMIT_SIGPENDING`表示等待的信号。

接下来，设置用户空间的限制。如下：

```C
	for (i = 0; i < UCOUNT_COUNTS; i++) {
		init_user_ns.ucount_max[i] = max_threads/2;
	}
```

* **CPU状态设置**

在开启`CONFIG_VMAP_STACK`的情况下，设置`CPUHP_BP_PREPARE_DYN`状态的回调函数。

* **`init_task`锁设置**

`lockdep_init_task(&init_task)`设置`init_task`的锁相关状态。

* **探针初始化**

`uprobes_init()`函数初始化探针，在[kernel/events/uprobes.c](https://github.com/torvalds/linux/blob/v5.4/kernel/events/uprobes.c#L2350)中实现。

## 5 缓存初始化

* **`proc_caches_init`**
  
`proc_caches_init`函数在[kernel/fork.c](https://github.com/torvalds/linux/blob/v5.4/kernel/fork.c#L2690)中实现。调用`kmem_cache_create`函数分配不同的缓存。包括:

* `sighand_cache`: 进程已分配信号处理程序；
* `signal_cache` : 进程信号描述符；
* `files_cache` : 进程打开的文件信息；
* `fs_cache` : 文件系统信息；
* `mm_struct` : 内存信息；
* `vm_area_struct` : 内存区域信息；

`proc_caches_init`函数的最后，调用`mmap_init`函数初始化SLAB虚拟内存区域；`nsproxy_cache_init`函数创建`nsproxy`缓存。

* **`uts_ns_init`**

`uts_ns_init`函数在[kernel/utsname.c](https://github.com/torvalds/linux/blob/v5.4/kernel/utsname.c#L171)中实现，创建`uts_namespace`缓存。

* **`buffer_init`**

`buffer_init`函数在[fs/buffer.c](https://github.com/torvalds/linux/blob/v5.4/fs/buffer.c#L3449)中实现，创建`buffer_head`缓存。`struct buffer_head`结构在[include/linux/buffer_head.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/buffer_head.h#L63)中定义，用来管理缓冲区。接下来，计算内存中缓冲区的大小并设置`10%`的内存量作为缓存。如下：

```C
	nrpages = (nr_free_buffer_pages() * 10) / 100;
	max_buffer_heads = nrpages * (PAGE_SIZE / sizeof(struct buffer_head));
```

* **`key_init`**

`key_init`函数在[security/keys/key.c](https://github.com/torvalds/linux/blob/v5.4/security/keys/key.c#L1177)中实现，初始化key管理状态。

首先，创建`key_jar`缓存；接下来，添加特殊的key类型（如：`key_type_keyring`, `key_type_dead`, `key_type_user`, `key_type_logon`）；最后，初始化`root_key_user`，并添加到`key_user_tree`中。

* **`security_init`**

`security_init`函数在[security/security.c](https://github.com/torvalds/linux/blob/v5.4/security/security.c#L354)中实现，初始化安全相关。

* **`vfs_caches_init`**

`vfs_caches_init`函数在[fs/dcache.c](https://github.com/torvalds/linux/blob/v5.4/fs/dcache.c#L3204)中实现，初始化VFS相关的不同缓存。包括：

* `names_cache` : 文件路径缓存；
* `dcache_init`函数创建`dentry`缓存；建立`Dentry cache`哈希表；
* `inode_init`函数创建`inode_cache`缓存；建立`Inode-cache`哈希表；
* `files_init`函数创建`filp`缓存；
* `files_maxfiles_init`函数计算支持的最大文件数；
* `mnt_init`函数在[fs/namespace.c](https://github.com/torvalds/linux/blob/v5.4/fs/namespace.c#L3745)中实现。创建`mnt_cache`缓存；建立`Mount-cache`和`Mountpoint-cache`哈希表；初始化并分配共享内存挂载`kernfs`；
* `bdev_cache_init`函数在[fs/block_dev.c](https://github.com/torvalds/linux/blob/v5.4/fs/block_dev.c#L844)中实现，初始化块设备。创建`bdev_cache`缓存；注册`bdev`文件系统；
* `chrdev_init`函数在[fs/char_dev.c](https://github.com/torvalds/linux/blob/v5.4/fs/char_dev.c#L664)中实现，初始化字符设备。

* **`pagecache_init`**

`pagecache_init`函数在[mm/filemap.c](https://github.com/torvalds/linux/blob/v5.4/mm/filemap.c#L1005)中实现。初始化页表等待队列和缓存回写时CPU回调函数。

* **`signals_init`**

`signals_init`函数在[kernel/signal.c](https://github.com/torvalds/linux/blob/v5.4/kernel/signal.c#L4570)中实现。在检查信号设置后，创建`sigqueue`缓存。

* **`seq_file_init`**

`seq_file_init`函数在[fs/seq_file.c](https://github.com/torvalds/linux/blob/v5.4/fs/seq_file.c#L1108)中实现。创建`seq_file`缓存。

## 6 `procfs`初始化（`proc_root_init`）

`proc_root_init`函数创建[procfs](https://en.wikipedia.org/wiki/Procfs)的根节点。在[fs/proc/root.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/root.c#L215)中实现。主要函数如下：

`proc_init_kmemcache`函在[fs/proc/inode.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/inode.c#L87)中实现。创建`proc_inode_cache`, `pde_opener`, `proc_dir_entry`的缓存。
`set_proc_pid_nlink`函在[fs/proc/base.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/base.c#L3716)中实现。计算`tid_base_stuff`和`tgid_base_stuff`连接项的数量。
`proc_self_init`函在[fs/proc/self.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/self.c#L70)中实现。获取`self`目录下inode的数量。`/proc/self`目录指向文件系统中`/proc`目录。
`proc_thread_self_init`函在[fs/proc/thread_self.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/thread_self.c#L70)中实现。获取`thread_self`目录下inode的数量。
`proc_symlink`函数在[fs/proc/generic.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/generic.c#L439)中实现，创建链接目录。这里创建`/proc/self/mounts`的链接目录，用于包含挂载点。
`proc_net_init`函数在[fs/proc/proc_net.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/proc_net.c#L388)中实现。创建`/proc/self/net`的连接目录；注册网络系统的`pernet_operations`操作。
`proc_mkdir`函数在[fs/proc/generic.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/generic.c#L491)中实现，创建目录。接下来，创建了`fs`, `driver`, `bus`等目录。
`proc_create_mount_point`函数在[fs/proc/generic.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/generic.c#L498)中实现，创建挂载点。接下来，创建了`fs/nfsd`挂载点。
`proc_tty_init`函数在[fs/proc/proc_tty.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/proc_tty.c#L165)中实现。初始化`/proc/tty`子树。创建`tty`和`tty/ldisc`目录；创建`tty/driver`目录；注册`ldiscs`和`drivers`这两个seq文件操作。
`proc_sys_init`函数在[fs/proc/proc_sysctl.c](https://github.com/torvalds/linux/blob/v5.4/fs/proc/proc_sysctl.c#L1717)中实现。创建`/proc/sys`目录，并初始化[sysctl](https://en.wikipedia.org/wiki/Sysctl)。
`register_filesystem`函数注册文件系统，这里注册`proc_fs_type`的文件系统。

## 7 `start_kernel`的其他初始化

`nsfs_init`函数在[fs/nsfs.c](https://github.com/torvalds/linux/blob/v5.4/fs/nsfs.c#L279)中实现。初始化namespace文件系统。
`cpuset_init`函数在[kernel/cgroup/cpuset.c](https://github.com/torvalds/linux/blob/v5.4/kernel/cgroup/cpuset.c#L2892)中实现。在系统启动后初始化cpuset。
`cgroup_init`函数在[kernel/cgroup/cgroup.c](https://github.com/torvalds/linux/blob/v5.4/kernel/cgroup/cgroup.c#L5716)中实现。初始化cgroup。
`taskstats_init_early`函数在[kernel/taskstats.c](https://github.com/torvalds/linux/blob/v5.4/kernel/taskstats.c#L688)中实现。创建`taskstats`缓存；初始化percpu中`listener_array`变量。
`delayacct_init`函数在[kernel/delayacct.c](https://github.com/torvalds/linux/blob/v5.4/kernel/delayacct.c#L28)中实现。创建`task_delay_info`缓存；初始化`init_task`延时账户。
`poking_init`函数在[arch/x86/mm/init.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/init.c#L710)中实现。初始化内存戳地址。
`check_bugs`函数在[arch/x86/kernel/cpu/bugs.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/bugs.c#L76)中实现。修正一些平台相关的bug。
`acpi_subsystem_init`函数在[drivers/acpi/bus.c](https://github.com/torvalds/linux/blob/v5.4/drivers/acpi/bus.c#L1091)中实现。完成ACPI早期初始化。
`arch_post_acpi_subsys_init`函数在[arch/x86/kernel/process.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/process.c#L735)中实现。进行ACPI初始化平台相关操作。
`sfi_init_late`函数在[drivers/sfi/sfi_core.c](https://github.com/torvalds/linux/blob/v5.4/drivers/sfi/sfi_core.c#L501)中实现。完成SFI初始化。

## 8 结束语

本文描述了Linux内核平台后的初始化过程，主要CPU设置、调度处理程序初始化、RCU初始化、缓存、procfs初始化等。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
