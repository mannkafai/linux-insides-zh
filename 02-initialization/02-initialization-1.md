# Linux内核初始化 （第一部分）

## 0 从引导过程到初始化

在上一章Linux内核引导过程中，我们已经解压缩Linux内核镜像，并加载到内存中，为执行内核代码做好了准备。在本章，我们将继续探究内核的初始化过程，即在启动`pid 1`进程前内核的初始化过程。

在上一章的最后一部分，我们跟踪到了[arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/head_64.S#L540)中的`jmp`指令:

```C
/*
 * Jump to the decompressed kernel.
 */
	jmp	*%rax
```

此时，`%rax`保存的是Linux内核入口点。

## 1 内核初始化的入口点

解压缩后的内核镜像的入口点定义在[arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head_64.S#L53)。

```C
	.text
	__HEAD
	.code64
	.globl startup_64
startup_64:
	UNWIND_HINT_EMPTY
```

`.text`在[arch/x86/kernel/vmlinux.lds.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/vmlinux.lds.S#L121)链接脚本文件中定义：

```C
	/* Text and read-only data */
	.text :  AT(ADDR(.text) - LOAD_OFFSET) {
		_text = .;
		_stext = .;
		/* bootstrapping code */
        ...
		/* End of text section */
		_etext = .;
	} :text = 0x9090
```

在这个链接脚本中，`_text = .`指示当前位置的地址，在`x86_64`下定义为`. = __START_KERNEL;`。

`__START_KERNEL`在[rch/x86/include/asm/page_types.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page_types.h#L45)文件中定义，由内核映射的虚拟基址和物理地址起始点相加得到：

```C
#define __PHYSICAL_START	ALIGN(CONFIG_PHYSICAL_START, CONFIG_PHYSICAL_ALIGN)
#define __START_KERNEL		(__START_KERNEL_map + __PHYSICAL_START)
```

即：

* Linux内核的物理基址(`__PHYSICAL_START`) - `0x1000000`;
* Linux内核的虚拟基址(`__START_KERNEL`) - `0xffffffff81000000`;

### 1.1 验证CPU(`verify_cpu`)

进入内核初始化后，需要建立函数调用栈，检验CPU信息。`verify_cpu`在[arch/x86/kernel/verify_cpu.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/verify_cpu.S#L34)中定义，验证CPU是否运行在长模式，是否SSE。

### 1.2 页表修正(`__startup_64`)

`__startup_64`函数在[arch/x86/kernel/head64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head64.c#L113)中定义，其功能为执行页表修复，根据SME状态将`pgd`地址修改`%cr3`寄存器。

```C
unsigned long __head __startup_64(unsigned long physaddr,
				  struct boot_params *bp)
{
    ...
    ...
}
```

#### 1.2.1 `5级页表`修正（`check_la57_support`）

进入`__startup_64`函数后，首先调用`check_la57_support`检查并修正5级页表。

`check_la57_support`根据`CONFIG_X86_5LEVEL`配置与否有不同的实现方式。在没有定义（即，没有配置5级页表）的情况下，直接返回`false`；在定义（即，开启5级页表）的情况下，代码如下：

```C
static bool __head check_la57_support(unsigned long physaddr)
{
	/*
	 * 5-level paging is detected and enabled at kernel decomression
	 * stage. Only check if it has been enabled there.
	 */
	if (!(native_read_cr4() & X86_CR4_LA57))
		return false;

	*fixup_int(&__pgtable_l5_enabled, physaddr) = 1;
	*fixup_int(&pgdir_shift, physaddr) = 48;
	*fixup_int(&ptrs_per_p4d, physaddr) = 512;
	*fixup_long(&page_offset_base, physaddr) = __PAGE_OFFSET_BASE_L5;
	*fixup_long(&vmalloc_base, physaddr) = __VMALLOC_BASE_L5;
	*fixup_long(&vmemmap_base, physaddr) = __VMEMMAP_BASE_L5;

	return true;
}
```

其中`fixup_int`、`fixup_long`调用`fixup_pointer`获取对应的物理地址。`fixup_pointer`函数实现如下：

```C
static void __head *fixup_pointer(void *ptr, unsigned long physaddr)
{
	return ptr - (void *)_text + (void *)physaddr;
}
```

在默认情况下（即，只有4级页表情况下且定义`CONFIG_X86_5LEVEL`），这些初始值为：

```C
#ifdef CONFIG_X86_5LEVEL
unsigned int __pgtable_l5_enabled __ro_after_init;
unsigned int pgdir_shift __ro_after_init = 39;
EXPORT_SYMBOL(pgdir_shift);
unsigned int ptrs_per_p4d __ro_after_init = 1;
EXPORT_SYMBOL(ptrs_per_p4d);
#endif

#ifdef CONFIG_DYNAMIC_MEMORY_LAYOUT
unsigned long page_offset_base __ro_after_init = __PAGE_OFFSET_BASE_L4;
EXPORT_SYMBOL(page_offset_base);
unsigned long vmalloc_base __ro_after_init = __VMALLOC_BASE_L4;
EXPORT_SYMBOL(vmalloc_base);
unsigned long vmemmap_base __ro_after_init = __VMEMMAP_BASE_L4;
EXPORT_SYMBOL(vmemmap_base);
#endif
```

#### 1.2.2 计算实际偏移地址差

在这里，我们需要验证加载的物理地址（`physaddr`）是否有效。验证的过程如下：

* 检验加载地址是否过大，如果超过`MAX_PHYSMEM_BITS`，则是无效地址。

```C
	/* Is the address too large? */
	if (physaddr >> MAX_PHYSMEM_BITS)
		for (;;);
```

`MAX_PHYSMEM_BITS`定义如下：

```C
# define MAX_PHYSMEM_BITS	(pgtable_l5_enabled() ? 52 : 46)
```

* 计算实际运行地址与编译地址间偏差

在上面我们可以看到，Linux内核默认运行的物理地址为`0x1000000`。由于可能开启`KASLR`，实际加载的地址有变化，需要计算偏差。计算过程如下：

```C
load_delta = physaddr - (unsigned long)(_text - __START_KERNEL_map);
```

* 检查偏差是否对齐

在计算偏差后，检查偏差是否按照`2MB`对齐。代码如下：

```C
	/* Is the address not 2M aligned? */
	if (load_delta & ~PMD_PAGE_MASK)
		for (;;);
```

`PMD_PAGE_MASK`代表中层页目录（Page middle directory）掩码位，定义如下：

```C
#define PMD_PAGE_SIZE		(_AC(1, UL) << PMD_SHIFT)
#define PMD_PAGE_MASK		(~(PMD_PAGE_SIZE-1))

#define PMD_SHIFT	21
```

* 计算SME偏差

在SME开启的情况下，计算其偏差。如下：

```C
	sme_enable(bp);
	load_delta += sme_get_me_mask();
```

#### 1.2.3 修正页表基地址

接下来，我们修正页表中的物理地址。在上一章内核初始化过程中，我们初始化了`4G`的页表。现在我们需要修正页表中物理地址，修正的页表包括：

```C
	pgd = fixup_pointer(&early_top_pgt, physaddr);
	p4d = fixup_pointer(&level4_kernel_pgt, physaddr);
	pud = fixup_pointer(&level3_kernel_pgt, physaddr);
	pmd = fixup_pointer(level2_fixmap_pgt, physaddr);
```

现在，我们看下`early_top_pgt`, `level4_kernel_pgt`, `level3_kernel_pgt`, `level2_fixmap_pgt`的定义。

```C
NEXT_PGD_PAGE(early_top_pgt)
	.fill	512,8,0
	.fill	PTI_USER_PGD_FILL,8,0

#ifdef CONFIG_X86_5LEVEL
NEXT_PAGE(level4_kernel_pgt)
	.fill	511,8,0
	.quad	level3_kernel_pgt - __START_KERNEL_map + _PAGE_TABLE_NOENC
#endif

NEXT_PAGE(level3_kernel_pgt)
	.fill	L3_START_KERNEL,8,0
	/* (2^48-(2*1024*1024*1024)-((2^39)*511))/(2^30) = 510 */
	.quad	level2_kernel_pgt - __START_KERNEL_map + _KERNPG_TABLE_NOENC
	.quad	level2_fixmap_pgt - __START_KERNEL_map + _PAGE_TABLE_NOENC

NEXT_PAGE(level2_kernel_pgt)
	PMDS(0, __PAGE_KERNEL_LARGE_EXEC,
		KERNEL_IMAGE_SIZE/PMD_SIZE)

NEXT_PAGE(level2_fixmap_pgt)
	.fill	(512 - 4 - FIXMAP_PMD_NUM),8,0
	pgtno = 0
	.rept (FIXMAP_PMD_NUM)
	.quad level1_fixmap_pgt + (pgtno << PAGE_SHIFT) - __START_KERNEL_map \
		+ _PAGE_TABLE_NOENC;
	pgtno = pgtno + 1
	.endr
	/* 6 MB reserved space + a 2MB hole */
	.fill	4,8,0

NEXT_PAGE(level1_fixmap_pgt)
	.rept (FIXMAP_PMD_NUM)
	.fill	512,8,0
	.endr
```

* `early_top_pgt`
  
首先，我们看到`early_top_pgt`，它开始的`4096`字节填充为0（在开启`CONFIG_PAGE_TABLE_ISOLATION`的情况下，为`8192`字节），即我们不使用前`512`（或前`1024`）项页表；

* `level4_kernel_pgt`
  
在启用`CONFIG_X86_5LEVEL`的情况下，`level4_kernel_pgt`的前`511`项为0，即我们不使用这些页表。之后一项值为`evel3_kernel_pgt - __START_KERNEL_map + _PAGE_TABLE_NOENC`。

`__START_KERNEL_map`是内核的虚拟基地址，因此减去`__START_KERNEL_map`后就得到了`level3_kernel_pgt`的物理地址。`_PAGE_TABLE_NOENC`是页表项的访问权限，定义如下：

```C
#define _KERNPG_TABLE_NOENC   (_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | \
                   _PAGE_DIRTY)
#define _PAGE_TABLE_NOENC     (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | \
                   _PAGE_ACCESSED | _PAGE_DIRTY)
```

* `level3_kernel_pgt`

`level3_kernel_pgt`前`510`项为0，`L3_START_KERNEL`值为0。接下来2项为`level2_kernel_pgt`和`level2_fixmap_pgt`的物理地址。

* `level2_kernel_pgt`

`level2_kernel_pgt`页表项包括映射内核的PMD的物理地址。它调用`PDMS`宏创建`KERNEL_IMAGE_SIZE/PMD_SIZE`个页表项，`KERNEL_IMAGE_SIZE`值为`512MB`，即创建256个页表项。`KERNEL_IMAGE_SIZE`在[arch/x86/include/asm/page_64_types.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page_64_types.h#L74)定义。

* `level2_fixmap_pgt`

`level2_fixmap_pgt`前`506`项为0；接下来2项为`level1_fixmap_pgt`的页表项；3项（6MB）的预留项和1项（2MB）的内存洞。

`FIXMAP_PMD_NUM`在[arch/x86/include/asm/fixmap.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/fixmap.h#L23)定义，定义如下：

```C
#define FIXMAP_PMD_NUM	2
/* fixmap starts downwards from the 507th entry in level2_fixmap_pgt */
#define FIXMAP_PMD_TOP	507
```

* `level1_fixmap_pgt`

`level1_fixmap_pgt`包括两个页，每个页中512项都置为0。

在了解到上面的定义后，接下来，初始化`pgd`, `p4d`, `pud`, `pmd`项等，代码如下：

```C
	p = pgd + pgd_index(__START_KERNEL_map);
	if (la57)
		*p = (unsigned long)level4_kernel_pgt;
	else
		*p = (unsigned long)level3_kernel_pgt;
	*p += _PAGE_TABLE_NOENC - __START_KERNEL_map + load_delta;

	if (la57) {
		p4d = fixup_pointer(&level4_kernel_pgt, physaddr);
		p4d[511] += load_delta;
	}

	pud = fixup_pointer(&level3_kernel_pgt, physaddr);
	pud[510] += load_delta;
	pud[511] += load_delta;

	pmd = fixup_pointer(level2_fixmap_pgt, physaddr);
	for (i = FIXMAP_PMD_TOP; i > FIXMAP_PMD_TOP - FIXMAP_PMD_NUM; i--)
		pmd[i] += load_delta;
```

在这之后我们得到了：

```C
`la57`启用的情况下：
early_top_pgt[511] -> level4_kernel_pgt[0]
level4_kernel_pgt[511] -> level3_kernel_pgt[0]

`la57`没有启用的情况下：
early_top_pgt[511] -> level3_kernel_pgt[0]

level3_kernel_pgt[510] -> level2_kernel_pgt[0]
level3_kernel_pgt[511] -> level2_fixmap_pgt[0]
level2_kernel_pgt[0]   -> 512 MB kernel mapping
level2_fixmap_pgt[507] -> level1_fixmap_pgt[1]
level2_fixmap_pgt[506] -> level1_fixmap_pgt[0]
```

注意，我们并没有修正`early_top_pgt`和其他页目录的基地址，我们会在构造、填充这些页目录时修正。在修正了页表基址后，我们可以开始构造这些页目录了。

#### 1.2.4 设置标识映射页表

现在我们进行对标识(identity)区域进行内存映射，这个区域虚拟地址以相同的方式映射到物理地址上。首先，将`early_dynamic_pgts`的第一个和第二个页表项设置为`pud`和`pmd`，代码如下：

```C
	next_pgt_ptr = fixup_pointer(&next_early_pgt, physaddr);
	pud = fixup_pointer(early_dynamic_pgts[(*next_pgt_ptr)++], physaddr);
	pmd = fixup_pointer(early_dynamic_pgts[(*next_pgt_ptr)++], physaddr);
```

`early_dynamic_pgts`的定义如下，它保存了早期的`64`个临时页表。

```C
NEXT_PAGE(early_dynamic_pgts)
	.fill	512*EARLY_DYNAMIC_PAGE_TABLES,8,0
```

接下来，初始化`pgtable_flags`，将每个页表标记设置为`_KERNPG_TABLE_NOENC + sme_get_me_mask()`。

* `pgd`
  
在`5级页表`启用的情况下，在获取`p4d`后进行后初始化；否则，直接初始化`pgd`。如下：

```C
	if (la57) {
		p4d = fixup_pointer(early_dynamic_pgts[(*next_pgt_ptr)++],
				    physaddr);

		i = (physaddr >> PGDIR_SHIFT) % PTRS_PER_PGD;
		pgd[i + 0] = (pgdval_t)p4d + pgtable_flags;
		pgd[i + 1] = (pgdval_t)p4d + pgtable_flags;

		i = physaddr >> P4D_SHIFT;
		p4d[(i + 0) % PTRS_PER_P4D] = (pgdval_t)pud + pgtable_flags;
		p4d[(i + 1) % PTRS_PER_P4D] = (pgdval_t)pud + pgtable_flags;
	} else {
		i = (physaddr >> PGDIR_SHIFT) % PTRS_PER_PGD;
		pgd[i + 0] = (pgdval_t)pud + pgtable_flags;
		pgd[i + 1] = (pgdval_t)pud + pgtable_flags;
	}
```

* `pud`

`pud`初始化过程和`pgd`类似。如下：

```C
	i = physaddr >> PUD_SHIFT;
	pud[(i + 0) % PTRS_PER_PUD] = (pudval_t)pmd + pgtable_flags;
	pud[(i + 1) % PTRS_PER_PUD] = (pudval_t)pmd + pgtable_flags;
```

* `pmd`

`pmd`初始化`_end - _text`大小的页表，其页表项(`pmd_entry`)不支持`__PAGE_KERNEL_*`位。如下：

```C
	pmd_entry = __PAGE_KERNEL_LARGE_EXEC & ~_PAGE_GLOBAL;
	/* Filter out unsupported __PAGE_KERNEL_* bits: */
	mask_ptr = fixup_pointer(&__supported_pte_mask, physaddr);
	pmd_entry &= *mask_ptr;
	pmd_entry += sme_get_me_mask();
	pmd_entry +=  physaddr;

	for (i = 0; i < DIV_ROUND_UP(_end - _text, PMD_SIZE); i++) {
		int idx = i + (physaddr >> PMD_SHIFT);

		pmd[idx % PTRS_PER_PMD] = pmd_entry + i * PMD_SIZE;
	}
```

#### 1.2.5 修正内核程序地址

* 修正`代码段和数据段`虚拟地址
  
接下来，修正内核程序中的`_text`到`_end`区域映射的内存，将`_text`之前和`_end`后的区域标记为不存在(`~_PAGE_PRESENT`)。

```C
	/* fixup pages that are part of the kernel image */
	for (; i <= pmd_index((unsigned long)_end); i++)
		if (pmd[i] & _PAGE_PRESENT)
			pmd[i] += load_delta;
```

* 修正实际的物理地址

```C
	*fixup_long(&phys_base, physaddr) += load_delta - sme_get_me_mask();
```

`phys_base`为`level2_kernel_pgt`中的第一个项。

* 修正`.bss..decrypted`区域

接下来，调用`sme_encrypt_kernel`加密内核。在`SME`启用时加密内核，并`.bss..decrypted`区域清除加密。

```C
	if (mem_encrypt_active()) {
		vaddr = (unsigned long)__start_bss_decrypted;
		vaddr_end = (unsigned long)__end_bss_decrypted;
		for (; vaddr < vaddr_end; vaddr += PMD_SIZE) {
			i = pmd_index(vaddr);
			pmd[i] -= sme_get_me_mask();
		}
	}
```

#### 1.2.6 初始化`pgdir`返回

`__startup_64`函数的最后一步是返回初始化`pgdir`页表项，修改到`%cr3`中。返回值为：`return sme_get_me_mask();`。

### 1.3 计算跳转地址

现在，我们回到`arch/x86/kernel/head_64.S`，接下来计算跳转地址：

```C
	addq	$(early_top_pgt - __START_KERNEL_map), %rax
```

将`early_top_pgt`的物理地址加到`%rax`上，（`%rax`保存了`SME`加密掩码）.

## 2 跳转到内核入口点前CPU设置

接下来，进行CPU设置，设置CPU工作在相应状态下。其中状态定义可参考[Control register](https://en.wikipedia.org/wiki/Control_register)。Linux内核关于寄存器的状态在[arch/x86/include/uapi/asm/processor-flags.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/uapi/asm/processor-flags.h)和[arch/x86/include/asm/msr-index.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/msr-index.h)文件中定义。

### 2.1 控制寄存器设置和CPU检查

* 分页设置(`%cr4`) - 开启CPU`PAE`，`PGE`标记，尝试开启`LA57`标记；
* 页表地址设置(`%cr3`) - 设置`4级或5级`页表到`cr3`寄存器，将`phys_base`地址加载到`%cr3`。
* 确保执行执行的是虚拟地址 - 将`$1f`地址放到`rax`寄存器中，并跳转到改地址。验证是否运行的是虚拟地址；
* 是否支持`nx` - 通过`cpuid`指令执行`0x80000001`指令，验证CPU是否支持`nx`；
* 设置`EFER`（Extended Feature Enable Register）- 设置CPU支持系统调用（System Call），并尝试设置`nx`；
* 设置`%cr0` - 设置`%cr0`为`CR0_STATE`状态。即：

```C
#define CR0_STATE	(X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | \
			 X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | \
			 X86_CR0_PG)
```

### 2.2 设置函数栈（`%rsp`）

设置`rsp`函数栈为`initial_stack`。`initial_stack`在同一个文件中定义：

```C
GLOBAL(initial_stack)
	.quad  init_thread_union + THREAD_SIZE - SIZEOF_PTREGS
```

`THREAD_SIZE`在[arch/x86/include/asm/page_64_types.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page_64_types.h#L15)中定义，如下：

```C
#ifdef CONFIG_KASAN
#define KASAN_STACK_ORDER 1
#else
#define KASAN_STACK_ORDER 0
#endif

#define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
```

`THREAD_SIZE`的大小根据[KASAN](https://github.com/torvalds/linux/blob/v5.4/Documentation/dev-tools/kasan.rst)配置与否不同，没有配置的情况下4个页大小，开启的情况下8个页大小，表示线程栈的大小。

为什么是`线程（thread）`？我们知道一个[进程(Process)](https://en.wikipedia.org/wiki/Process_(computing))可能有[父进程(Parent Process)](https://en.wikipedia.org/wiki/Parent_process)和[子进程(Child process)](https://en.wikipedia.org/wiki/Child_process)。父进程和子进程使用不同的栈空间，每个新进程都会拥有一个新的内核栈。在Linux内核中，这个栈由`thread_union`结构表示，`thread_union`在[include/linux/sched.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/sched.h#L1628)定义。如下：

```C
union thread_union {
#ifndef CONFIG_ARCH_TASK_STRUCT_ON_STACK
	struct task_struct task;
#endif
#ifndef CONFIG_THREAD_INFO_IN_TASK
	struct thread_info thread_info;
#endif
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};
```

`CONFIG_ARCH_TASK_STRUCT_ON_STACK`内核配置选项只能适用于`ia64`架构；`CONFIG_THREAD_INFO_IN_TASK`配置选项在`x86_64`架构下是开启的。因此，`thread_union`使用的是`struct task_struct`。

`init_thread_union`在[include/asm-generic/vmlinux.lds.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/vmlinux.lds.h#L323)中定义，

```C
#define INIT_TASK_DATA(align)						\
	. = ALIGN(align);						\
	__start_init_task = .;						\
	init_thread_union = .;						\
	init_stack = .;							\
	KEEP(*(.data..init_task))					\
	KEEP(*(.data..init_thread_info))				\
	. = __start_init_task + THREAD_SIZE;				\
	__end_init_task = .;
```

这个宏在[arch/x86/kernel/vmlinux.lds.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/vmlinux.lds.S#L165)文件中使用，如下：

```C
.data : AT(ADDR(.data) - LOAD_OFFSET) {
    ...
    INIT_TASK_DATA(THREAD_SIZE)
    ...
} :data
```

因此，`initial_stack`指向`thread_union.stack` + `THREAD_SIZE`(16KB) - `SIZEOF_PTREGS`(8B，函数栈尾检测约定).

### 2.3 重置`EFLAGS`寄存器

将[EFLAGS](https://en.wikipedia.org/wiki/FLAGS_register)寄存器置零。

### 2.4 更新全局描述表

更新`lgdt`为`early_gdt_descr`，`early_gdt_descr`在同一个文件定义，如下：

```C
	.data
	.align 16
	.globl early_gdt_descr
early_gdt_descr:
	.word	GDT_ENTRIES*8-1
early_gdt_descr_base:
	.quad	INIT_PER_CPU_VAR(gdt_page)
```

`GDT_ENTRIES`值为`32`。`gdt_page`在[arch/x86/include/asm/desc.h](https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/desc.h#L44)中定义，如下：

```C
struct gdt_page {
	struct desc_struct gdt[GDT_ENTRIES];
} __attribute__((aligned(PAGE_SIZE)));
```

`desc_struct`的定义如下：

```C
/* 8 byte segment descriptor */
struct desc_struct {
	u16	limit0;
	u16	base0;
	u16	base1: 8, type: 4, s: 1, dpl: 2, p: 1;
	u16	limit1: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
} __attribute__((packed));
```

`desc_struct`结构和`GDT`描述符类似，`gdt_page`结构以`PAGE_SIZE`大小对齐，即`gdt`占用一个页大小。

`INIT_PER_CPU_VAR`在[arch/x86/include/asm/percpu.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/percpu.h#L38)定义，如下：

```C
#define INIT_PER_CPU_VAR(var) init_per_cpu__##var
```

`INIT_PER_CPU_VAR`宏定义连接`init_per_cpu__`和给定的参数。`INIT_PER_CPU_VAR(gdt_page)`展开为`init_per_cpu__gdt_page`，在[arch/x86/kernel/vmlinux.lds.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/vmlinux.lds.S#L436)可以看到其定义。

```C
#define INIT_PER_CPU(x) init_per_cpu__##x = ABSOLUTE(x) + __per_cpu_load
INIT_PER_CPU(gdt_page);
INIT_PER_CPU(fixed_percpu_data);
INIT_PER_CPU(irq_stack_backing_store);
```

我们创建`PER_CPU`变量时，每个CPU都拥有一份自己的拷贝，这种类型的变量有很多优点，每个CPU都只访问自己的变量而不需要锁。

### 2.5 更新段寄存器

在将`%ds`, `%ss`, `%es`, `%fs`, `%gs`寄存器重置后，需要重新设置`%gs`寄存器，将其指向一个用于处理[中断(Interrupt)](https://en.wikipedia.org/wiki/Interrupt)的栈。

```C
	movl	$MSR_GS_BASE,%ecx
	movl	initial_gs(%rip),%eax
	movl	initial_gs+4(%rip),%edx
	wrmsr
```

`MSR_GS_BASE`在[arch/x86/include/asm/msr-index.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/msr-index.h#L21)定义，如下：

```C
#define MSR_GS_BASE		0xc0000101 /* 64bit GS base */
```

`initial_gs`在同一个文件中定义，如下：

```C
	GLOBAL(initial_gs)
	.quad	INIT_PER_CPU_VAR(fixed_percpu_data)
```

`fixed_percpu_data`在[arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/processor.h#L388)中定义，如下：

```C
struct fixed_percpu_data {
	/*
	 * GCC hardcodes the stack canary as %gs:40.  Since the
	 * irq_stack is the object at %gs:0, we reserve the bottom
	 * 48 bytes of the irq stack for the canary.
	 */
	char		gs_base[40];
	unsigned long	stack_canary;
};
```

我们把`MSR_GS_BASE`放入`ecx`寄存器，同时利用`wrmsr`指令向`eax`和`edx`处的地址加载数据（即指向`initial_gs`）。`cs`, `fs`, `ds`和`ss`段寄存器在64位模式下不用来寻址，但`fs`和`gs`可以使用，`fs`和`gs`有一个隐含的部分（与实模式下的`cs`段寄存器类似），这个隐含部分存储了一个描述符，其指向[Model Specific Registers](https://en.wikipedia.org/wiki/Model-specific_register)。因此上面的`0xc0000101`是一个`gs.base` MSR地址。当发生[系统调用(System call)](https://en.wikipedia.org/wiki/System_call)或者[中断(Interrupt)](https://en.wikipedia.org/wiki/Interrupt)时，入口点处并没有内核栈，因此`MSR_GS_BASE`将会用来存放中断栈。

### 2.6 跳转到C函数代码

经过上面的初始化后，我们终于可以进入C函数了。但是，我们现在还运行在标记映射空间上，必须跳转到完整的64位模式下，只能进行间接跳转。代码如下：

```C
	/* rsi is pointer to real mode structure with interesting info.
	   pass it to C */
	movq	%rsi, %rdi

.Ljump_to_C_code:
	pushq	$.Lafter_lret	# put return address on stack for unwinder
	xorl	%ebp, %ebp	# clear frame pointer
	movq	initial_code(%rip), %rax
	pushq	$__KERNEL_CS	# set correct cs
	pushq	%rax		# target address in negative space
	lretq
.Lafter_lret:
```

`%rsi`保存的是`bootparam`的地址(从实模式开始一直保存着)，将其放入`%rdi`（函数调用的第一个参数）。在向函数栈中压入`返回地址`，`__KERNEL_CS`，`initial_code`地址后，通过`lretq`指令弹出返回值(`%rax`)并跳转。`initial_code`在同一个文件中定义，如下：

```C
	.balign	8
	GLOBAL(initial_code)
	.quad	x86_64_start_kernel
```

可以看到`initial_code`为`x86_64_start_kernel`的函数地址，在[arch/x86/kernel/head64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head64.c#L425)中实现，如下：

```C
asmlinkage __visible void __init x86_64_start_kernel(char * real_mode_data)
{
    ...
}
```

## 3 结束语

本文描述了Linux内核初始化的第一部分，修正了内存页表并将CPU中的寄存器设置在正确状态。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
