# Linux内核地址随机化

## 0 介绍

在上一篇中，我们介绍了Linux内核引导过程的最后阶段。但是我们跳过了一些重要的，更高级的部分。

Linux内核入口的基地址为`LOAD_PHYSICAL_ADDR`，依赖于`CONFIG_PHYSICAL_START`的内核配置选项。`CONFIG_PHYSICAL_START`的默认值为`0x1000000`。因此，`LOAD_PHYSICAL_ADDR`的值可以根据内核配置选项修改，但是，在`CONFIG_RANDOMIZE_BASE`内核配置选项开启的情况下，Linux内核镜像的物理地址在解压缩后会加载到随机地址。

本文描述在`CONFIG_RANDOMIZE_BASE`内核配置选项开启的情况，内核镜像加载地址随机化的过程。

## 1 参数说明

在前一篇中，我们切换到长模式，跳转到内核解压缩入口点函数，即`extract_kernel`函数。调用`choose_random_location`函数获取随机地址。如下：

```C
asmlinkage __visible void *extract_kernel(void *rmode, memptr heap,
				  unsigned char *input_data,
				  unsigned long input_len,
				  unsigned char *output,
				  unsigned long output_len)
    ...
	choose_random_location((unsigned long)input_data, input_len,
				(unsigned long *)&output,
				needed_size,
				&virt_addr);
    ...
}
```

`choose_random_location`函数的声明如下：

```C
void choose_random_location(unsigned long input,
			    unsigned long input_size,
			    unsigned long *output,
			    unsigned long output_size,
			    unsigned long *virt_addr)

```

这个函数有5个入口参数。第一个参数`input`即`extract_kernel`函数中`input_data`参数，这个参数在[arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/head_64.S#L532)文件中传递。如下：

```C
	leaq	input_data(%rip), %rdx  /* input_data */
```

`input_data`通过[arch/x86/boot/compressed/mkpiggy.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/mkpiggy.c#L19)程序生成。在编译Linux内核的过程中，这个程序生成的输出信息在`arch/x86/boot/compressed/piggy.S`文件中，如下：

```C
.section ".rodata..compressed","a",@progbits
.globl z_input_len
z_input_len = 9203110
.globl z_output_len
z_output_len = 45043712
.globl input_data, input_data_end
input_data:
.incbin "arch/x86/boot/compressed/vmlinux.bin.gz"
input_data_end:
```

可以看到，它包含了4个全局的符号，`z_input_len`和`z_output_len`表示`vmlinux.bin.gz`文件压缩前和解压后的大小；`input_data`表示Linux内核镜像的原始文件的二进制内容，`input_data_end`表示Linux镜像压缩文件的文件尾。

因此，`choose_random_location`函数的第一个参数`input_data`表示嵌入`piggy.o`文件中压缩的内核镜像；第二个参数`input_size`表示压缩的内核镜像大小，即为`z_input_len`；第三个参数`output`表示解压缩后的内核镜像地址，即`startup_32`函数地址对齐到`2MiB`的边界地址；第四个参数`output_size`表示解压缩后的内核镜像大小，即`z_output_len`；第五个参数`virt_addr`即内核镜像加载的虚拟地址，默认值为`LOAD_PHYSICAL_ADDR`，即默认加载的物理地址。

`LOAD_PHYSICAL_ADDR`根据内核配置选项，如下：

```C
#define LOAD_PHYSICAL_ADDR ((CONFIG_PHYSICAL_START \
				+ (CONFIG_PHYSICAL_ALIGN - 1)) \
				& ~(CONFIG_PHYSICAL_ALIGN - 1))
```

## 2 实现过程

### 2.1 检查命令行参数

如果命令行参数有`nokaslr`选项，则退出`choose_random_location`函数，即内核加载地址不会随机化。

```C
	if (cmdline_find_option_bool("nokaslr")) {
		warn("KASLR disabled: 'nokaslr' on cmdline.");
		return;
	}
```

### 2.2 初始化内存映射信息

在启用随机地址后，首先需要初始化内存映射信息。

#### 2.2.1 计算页表偏移和设置加载标签

在启用`5级页表`的情况下，更新`pgdir_shift`, `ptrs_per_p4d`的值，分别设置为`48`和`512`。在只使用`4级页表`的情况下，值分别为`39`和`1`。

在此之后，我们添加`KASLR_FLAG`到内核加载标签，`boot_params->hdr.loadflags |= KASLR_FLAG;`。

#### 2.2.2 初始化页表映射（`initialize_identity_maps`）

`initialize_identity_maps`在[arch/x86/boot/compressed/kaslr_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/kaslr_64.c#L81)中实现。其功能是初始化页表映射信息，实现如下：

* **1. 获取SEV掩码**

`set_sev_encryption_mask`在[arch/x86/boot/compressed/mem_encrypt.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/mem_encrypt.S#L71)中实现。该函数功能是获取AMD SEV([AMD Secure Encrypted Virtualization](https://developer.amd.com/sev/#:~:text=AMD%20Secure%20Encrypted%20Virtualization%20%28SEV%29%20Uses%20one%20key,enablement%20in%20the%20guest%20operating%20system%20and%20hypervisor.))的加密掩码。

* **2.初始化`mapping_info`**

`mapping_info`是类型为`x86_mapping_info`，`x86_mapping_info`结构体在[arch/x86/include/asm/init.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/init.h#L5)定义。

```C
struct x86_mapping_info {
	void *(*alloc_pgt_page)(void *); /* allocate buf for page table */
	void *context;			 /* context for alloc_pgt_page */
	unsigned long page_flag;	 /* page flag for PMD or PUD entry */
	unsigned long offset;		 /* ident mapping offset */
	bool direct_gbpages;		 /* PUD level 1GB page support */
	unsigned long kernpg_flag;	 /* kernel pagetable flag override */
};
```

`x86_mapping_info`提供了内存映射信息，在前一部分(保护模式下)已经建立了`4GB`的页表。随机的位置可能会访问`4GB`以上的地址，所以可能需要新的页表。其字段说明如下：

* `alloc_pgt_page` - 分配全局页表的回调函数；
* `context` - 分配页表的示例；
* `page_flag` - PMD或PUD的标记；
* `kernpg_flag` - 是否覆盖内核页的标记；
* `offset` - 地址偏移量；
* `direct_gbpages` - 表示是否为大页，PUD级大小为1GB；

`mapping_info`的初始化为：

```C
	mapping_info.alloc_pgt_page = alloc_pgt_page;
	mapping_info.context = &pgt_data;
	mapping_info.page_flag = __PAGE_KERNEL_LARGE_EXEC | sme_me_mask;
	mapping_info.kernpg_flag = _KERNPG_TABLE;
```

`mapping_info.context`初始化为`pgt_data`，其结构定义如下：

```C
/* Used to track our page table allocation area. */
struct alloc_pgt_data {
	unsigned char *pgt_buf;
	unsigned long pgt_buf_size;
	unsigned long pgt_buf_offset;
};
```

`mapping_info.alloc_pgt_page`初始化为`alloc_pgt_page`，该回调函数分配一个新的页表，分配页表的代码如下：

```C
	entry = pages->pgt_buf + pages->pgt_buf_offset;
	pages->pgt_buf_offset += PAGE_SIZE;
```

* **3. 初始化`pgt_data`**

`pgt_data.pgt_buf_offset`设置为0；`pgt_data.pgt_buf`，`pgt_data.pgt_buf_size`根据BootLoader的引导协议(32bit或64位)不同设置不同的值。

在`64bit`引导协议下，设置正确的值后，还需要修改`top_level_pgt`，代码如下：

```C
		pgt_data.pgt_buf = _pgtable;
		pgt_data.pgt_buf_size = BOOT_PGT_SIZE;
		memset(pgt_data.pgt_buf, 0, pgt_data.pgt_buf_size);
		top_level_pgt = (unsigned long)alloc_pgt_page(&pgt_data);
```

### 2.3 避开保留的内存区域（`mem_avoid_init`）

在页表相关的数据初始化后，我们可以选择加压缩内核的随机地址，但我们不能选择任意地址，有一些保留的地址（如：initrd、cmdline、bootparams等）需要映射在固定位置。调用`mem_avoid_init`函数将收集保留的内存区域。

保留的区域收集到`mem_avoid`的数组中，如下：

```C
struct mem_vector {
	unsigned long long start;
	unsigned long long size;
};
static struct mem_vector mem_avoid[MEM_AVOID_MAX];

...
enum mem_avoid_index {
	MEM_AVOID_ZO_RANGE = 0,
	MEM_AVOID_INITRD,
	MEM_AVOID_CMDLINE,
	MEM_AVOID_BOOTPARAMS,
	MEM_AVOID_MEMMAP_BEGIN,
	MEM_AVOID_MEMMAP_END = MEM_AVOID_MEMMAP_BEGIN + MAX_MEMMAP_REGIONS - 1,
	MEM_AVOID_MAX,
};
```

除`INITRD`外，其他区域调用计算起始地址和大小后，调用`add_identity_map`函数添加到映射区域。每个区域映射的操作步骤如下，以`MEM_AVOID_ZO_RANGE`为例：

#### 2.3.1 计算映射的起始地址和大小

```C
	mem_avoid[MEM_AVOID_ZO_RANGE].start = input;
	mem_avoid[MEM_AVOID_ZO_RANGE].size = (output + init_size) - input;
	add_identity_map(mem_avoid[MEM_AVOID_ZO_RANGE].start,
			 mem_avoid[MEM_AVOID_ZO_RANGE].size);
```

#### 2.3.2 添加内存映射`add_identity_map`

`add_identity_map`在[arch/x86/boot/compressed/kaslr_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/kaslr_64.c#L130)中定义。`add_identity_map`函数将地址和大小对齐到`PMD_SIZE`（2MB）大小；然后调用`kernel_ident_mapping_init`函数。如下：

```C
	/* Align boundary to 2M. */
	start = round_down(start, PMD_SIZE);
	end = round_up(end, PMD_SIZE);
	if (start >= end)
		return;

	/* Build the mapping. */
	kernel_ident_mapping_init(&mapping_info, (pgd_t *)top_level_pgt,
				  start, end);
```

#### 2.3.3 内核内存映射（`kernel_ident_mapping_init`）

`kernel_ident_mapping_init`在[arch/x86/mm/ident_map.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/ident_map.c#L89)中定义。其功能是增加特定的页表映射信息，实现过程如下：

* **1. 设置分配标记**

首先，设置分配内存页的默认标记`kernpg_flag`，如下：

```C
	/* Set the default pagetable flags if not supplied */
	if (!info->kernpg_flag)
		info->kernpg_flag = _KERNPG_TABLE;

	/* Filter out unsupported __PAGE_KERNEL_* bits: */
	info->kernpg_flag &= __default_kernel_pte_mask;
```

`_KERNPG_TABLE`是一个宏定义，展开为：`(_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_ENC)`。

* **2. 分配页表**

在`5级页表`的情况下，按照`pgd -> p4d -> pud -> pmd`的顺序逐级访问建立页表；在`4级页表`的情况下，按照`pgd -> pud -> pmd`的顺序逐级访问建立页表。如下：

```C
for (; addr < end; addr = next) {
		pgd_t *pgd = pgd_page + pgd_index(addr);
		p4d_t *p4d;

		next = (addr & PGDIR_MASK) + PGDIR_SIZE;
		if (next > end)
			next = end;

		if (pgd_present(*pgd)) {
			p4d = p4d_offset(pgd, 0);
			result = ident_p4d_init(info, p4d, addr, next);
			if (result)
				return result;
			continue;
		}

		p4d = (p4d_t *)info->alloc_pgt_page(info->context);
		if (!p4d)
			return -ENOMEM;
		result = ident_p4d_init(info, p4d, addr, next);
		if (result)
			return result;
    ...
```

首先，确定`addr`在`pgd`下一项的地址，确保`next`在`end`区域内。如果`p4d`不存在，调用`x86_mapping_info.alloc_pgt_page`的回调函数分配一个新页，然后调用`ident_p4d_init`函数。

`ident_p4d_init`函数进行类似的操作，进行下一级页表的初始化。整个初始化的过程按照`ident_p4d_init -> ident_pud_init -> ident_pmd_init`的级别顺序初始化。

### 2.4 物理地址随机化

#### 2.4.1 选择最小可用的地址

随机内存地址应该小于512MB。

```C
	min_addr = min(*output, 512UL << 20);
```

#### 2.4.2 选择随机物理地址（`find_random_phys_addr`）

`find_random_phys_addr`函数在同一个文件中定义。实现过程如下：

* **1. 获取满足条件的内存区域**

调用`process_efi_entries`函数获取在整个内存区域中找到所有符合的区域，在不支持[EFI](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface)的系统，调用`process_e820_entries`函数在[E820](https://en.wikipedia.org/wiki/E820)内存区域寻找同样的区域。

所有找到的内存区域存放在`slot_areas`区域中，定义如下：

```C
struct slot_area {
	unsigned long addr;
	int num;
};
#define MAX_SLOT_AREA 100

static struct slot_area slot_areas[MAX_SLOT_AREA];
static unsigned long slot_max;
static unsigned long slot_area_index;
```

* **2. 随机选择区域**

`slots_fetch_random`函数调用`kaslr_get_random_long`获取随机数，随机选择一个内存范围，如下：

```C
	slot = kaslr_get_random_long("Physical") % slot_max;

	for (i = 0; i < slot_area_index; i++) {
		if (slot >= slot_areas[i].num) {
			slot -= slot_areas[i].num;
			continue;
		}
		return slot_areas[i].addr + slot * CONFIG_PHYSICAL_ALIGN;
	}
```

`kaslr_get_random_long`在[arch/x86/lib/kaslr.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/lib/kaslr.c#L49)中实现，根据不同的内核配置，基于不同的方式（如：RDRAND, RDTSC, i8254, random）等方式返回随机数。

#### 2.4.3 更新物理地址映射区域

获取随机的物理地址后，调用`add_identity_map`函数进行地址映射后，调用`finalize_identity_maps`更新`%cr3`寄存器。

### 2.5 虚拟地址随机化

在`x86_64`以外的架构下，虚拟地址和物理地址是同一个值。在`x86_64`架构下，调用`find_random_virt_addr`函数获取随机的虚拟地址。同获取随机物理地址类似，调用`kaslr_get_random_long`获取随机数进行检查后获取到虚拟地址。

```C
	/* Pick random virtual address starting from LOAD_PHYSICAL_ADDR. */
	if (IS_ENABLED(CONFIG_X86_64))
		random_addr = find_random_virt_addr(LOAD_PHYSICAL_ADDR, output_size);
	*virt_addr = random_addr;
```

此时，我们同时获取到了随机物理地址(`*output`)和虚拟地址(`*virt_addr`)。

## 3 结束语

本文描述了Linux内核启动过程中内核镜像物理地址和虚拟地址随机选择的过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
