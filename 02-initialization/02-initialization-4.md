
# Linux内核初始化 （第四部分）

## 0 平台相关初始化

在上一篇中`start_kernel`函数进行平台相关前的初始化，现在调用`setup_arch`函数进行平台相关初始化。

## 1 平台初始化函数（`setup_arch`）

`setup_arch`和`start_kernel`类似，比较复杂，调用了很多函数。既然是平台特性相关，我们需要重新返回`arch`文件夹。`setup_arch`在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup.c#L837)中实现，该函数只有一个参数 -- `command_line`的地址。接下来，我们看下其实现过程。

## 2 早期初始化

### 2.1 保留内存区域

* **保留`_text`到`__end_of_kernel_reserve`之间的内存区域**

```C
	memblock_reserve(__pa_symbol(_text),
			 (unsigned long)__end_of_kernel_reserve - (unsigned long)_text);
```

首先，保留`_text`到`__end_of_kernel_reserve`间的内存区域，`_text`和`__end_of_kernel_reserve`在[arch/x86/kernel/vmlinux.lds.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/vmlinux.lds.S#L122)中定义。

`memblock_reserve`将内存存放到`memblock`中的保留区域，关于`memblock`的介绍这里不详细介绍。

`__pa_symbol`是个宏定义，获取给定符号的物理地址。宏展开如下：

```C
#define __pa_symbol(x) \
	__phys_addr_symbol(__phys_reloc_hide((unsigned long)(x)))

#define __phys_reloc_hide(x)	(x)

#define __phys_addr_symbol(x) \
	((unsigned long)(x) - __START_KERNEL_map + phys_base)
```

* **保留第一个内存页**

为了预防[L1FT(L1 Terminal Fault)](https://github.com/torvalds/linux/blob/v5.4/Documentation/admin-guide/hw-vuln/l1tf.rst)侧信道攻击，保留第一个内存页。

```C
	memblock_reserve(0, PAGE_SIZE);
```

* **保留initrd内存**

调用`early_reserve_initrd`保留[initrd](http://en.wikipedia.org/wiki/Initrd)内存区域。首先，获取`RAM DISK`的基地址、大小和结束地址；在检查BootLoader提供的ramdisk信息后，保留内存区域。整个过程如下：

```C
	/* Assume only end is not page aligned */
	u64 ramdisk_image = get_ramdisk_image();
	u64 ramdisk_size  = get_ramdisk_size();
	u64 ramdisk_end   = PAGE_ALIGN(ramdisk_image + ramdisk_size);

	if (!boot_params.hdr.type_of_loader ||
	    !ramdisk_image || !ramdisk_size)
		return;		/* No initrd provided by bootloader */

	memblock_reserve(ramdisk_image, ramdisk_end - ramdisk_image);
```

基地址和大小通过`boot_params`获取，以调用`get_ramdisk_image`获取基地址为例：

```C
static u64 __init get_ramdisk_image(void)
{
	u64 ramdisk_image = boot_params.hdr.ramdisk_image;
	ramdisk_image |= (u64)boot_params.ext_ramdisk_image << 32;
	return ramdisk_image;
}
```

`ramdisk_image`的地址由两部分组成，`hdr.ramdisk_image`（32位的低位地址）和`ext_ramdisk_image`（32位高位地址），具体可参见[Documentation/x86/zero-page.rst](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/zero-page.rst)。

```text
0C0/004	ALL	ext_ramdisk_image	ramdisk_image high 32bits
```

### 2.2 OLPC检测

接下来，调用`olpc_ofw_detect`函数检测是否支持[OLPC(One Laptop per Child)](https://en.wikipedia.org/wiki/One_Laptop_per_Child)。在[arch/x86/platform/olpc/olpc_ofw.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/platform/olpc/olpc_ofw.c#L93)实现。

### 2.3 早期中断设置（`idt_setup_early_traps`）

接下来，我们调用`idt_setup_early_traps`函数，在[arch/x86/kernel/idt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/idt.c#L253)实现。如下：

```C
void __init idt_setup_early_traps(void)
{
	idt_setup_from_table(idt_table, early_idts, ARRAY_SIZE(early_idts),
			     true);
	load_idt(&idt_descr);
}

/*
 * Early traps running on the DEFAULT_STACK because the other interrupt
 * stacks work only after cpu_init().
 */
static const __initconst struct idt_data early_idts[] = {
	INTG(X86_TRAP_DB,		debug),
	SYSG(X86_TRAP_BP,		int3),
#ifdef CONFIG_X86_32
	INTG(X86_TRAP_PF,		page_fault),
#endif
};
```

可以看到，早期中断设置初始化`#DB`(debug)和`#BP`(int3)中断处理程序，并在`CONFIG_X86_32`开启的情况下初始化`#PF`(page fault)中断处理程序。

`idt_setup_from_table`的处理过程在上一篇有描述，这里不再描述。

* **`#DB`中断处理程序**

`debug`在[arch/x86/include/asm/traps.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/traps.h#L14)中声明。如下：

```C
asmlinkage void debug(void);
```

从`asmlinkage`属性可以看到`debug`是汇编语言实现的。同其他处理函数一样，`#DB`中断处理函数在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L1192)中实现。如下：

```C
idtentry debug do_debug	has_error_code=0 paranoid=1 shift_ist=IST_INDEX_DB ist_offset=DB_STACK_OFFSET
```

`idtentry`是一个定义中断/异常指令入口点的宏。如下：

```C
.macro idtentry sym do_sym has_error_code:req paranoid=0 shift_ist=-1 ist_offset=0 create_gap=0 read_cr2=0
ENTRY(\sym)
	UNWIND_HINT_IRET_REGS offset=\has_error_code*8

	/* Sanity check */
	.if \shift_ist != -1 && \paranoid != 1
	.error "using shift_ist requires paranoid=1"
	.endif

	.if \create_gap && \paranoid
	.error "using create_gap requires paranoid=0"
	.endif

    ...
```

`idtentry`支持8个参数：

* sym - 中断条目名称；
* do_sym - 中断处理程序的C函数；
* has_error_code - 在栈上是否有中断错误码；
* paranoid - 如果非零，表示可以切换到特殊栈；
* shift_ist - IST切换栈的次数，在切换栈时递减。为`#DB`特殊设置的，可能会出现递归栈。
* ist_offset - IST的偏移量；
* create_gap - 从内核模式切换时是否创建6个字的栈间隔；
* read_cr2 - 在调用C函数前，是否加载`cr2`寄存器值到第三个参数；

`idtentry`宏展开后，通过`ENTRY`宏属性定义中断处理程序（如：`debug`）。整个处理过程如下：

* 首先，检查输入参数是否正确；
* 检查是否有错误码(`has_error_code`)，无错误码时将`-1`压入栈中；
* 检查`paranoid`参数，检查处于用户模式时，按需切换栈空间；否则跳转到`idtentry_part`；
* 检查`create_gap`参数，检查处于用户模式时，跳转到`idtentry_part`；否则按需创建栈间隔；
* 接下来执行`idtentry_part`宏；

`idtentry_part`的执行过程如下：

* 检查`paranoid`参数是否切换栈空间，切换时调用`paranoid_entry`（保存通用寄存器值，按需切换用户态`gs`到内核态`gs`）；否则，调用`error_entry`（保存通用寄存器值，必要时切换`gs`）;
* 检查`read_cr2`参数，需要保存时，将`cr2`寄存器中值保存到`%r12`寄存器中；
* 检查`shift_ist`，不等于`-1`时调用`TRACE_IRQS_OFF_DEBUG`；否则调用`TRACE_IRQS_OFF`；`TRACE_IRQS_OFF_DEBUG`对`TRACE_IRQS_OFF`进行了封装；
* 检查`paranoid == 0`，且当前处于用户模式下；
* 保存`pt_regs`到`%rdi`；中断错误码到`%rsi`；`%r12`(保存的是`%cr2`)到`%rdx`；必要时减少`CPU_TSS_IST`值；
* 调用`do_sym`函数，如：`do_debug`;
* 中断处理完成后，必要时恢复`CPU_TSS_IST`值；
* 检查`paranoid`参数，通过`paranoid_exit`或`error_exit`恢复之前栈空间；
  
`#DB`中断处理程序调用C函数是`do_debug`函数，在[arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/traps.c#L709)中实现。它接收两个参数，`pt_regs`和`error_code`。

`#BP`中断处理程序类似，调用`do_int3`函数。

### 2.4 早期CPU相关设置

* **最大访问物理内存设置**
  
设置`boot_cpu_data`最大访问的物理内存；

* **CPU初始化**

调用`early_cpu_init`函数，在[arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/common.c#L1266)中实现。从`x86_cpu_dev.init`段获取CPU信息（如：供应商信息），并初始化`boot_cpu_data`。

* **Intel理想nops设置**

调用`arch_init_ideal_nops`函数，在[arch/x86/kernel/alternative.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/alternative.c#L202)中实现。根据`boot_cpu_data.x86_vendor`设置不同的`ideal_nops`。

* **跳转标签初始化**

调用`jump_label_init`函数，在[kernel/jump_label.c](https://github.com/torvalds/linux/blob/v5.4/kernel/jump_label.c#L453)中实现。初始化`__jump_table`段中跳转标签。跳转标签提升跳转的命中率，参见[Documentation/static-keys.txt](https://github.com/torvalds/linux/blob/v5.4/Documentation/static-keys.txt)。

### 2.5 早期ioremap初始化

通常有两种与设备通信的方式，`I/O端口`和`设备内存`。我们在Linux内核启动过程中见过第一种方式（通过`outb/inb`指令）。第二种方式将`I/O`物理地址映射到虚拟地址上，当CPU访问物理地址时，它可以读取到映射了`I/O`设备的内存。`ioremap`这种方式就是用来将设备内存映射到内核地址空间。

接下来调用`early_ioremap_init`函数，将I/O内存映射到内核地址空间，在[arch/x86/mm/ioremap.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/ioremap.c#L802)实现。

`early_ioremap_init`将`FIX_BTMAP_BEGIN`到`FIX_BTMAP_END`之间的固定虚拟地址进行映射。主要执行如下：

```C
	pmd_t *pmd;

#ifdef CONFIG_X86_64
	BUILD_BUG_ON((fix_to_virt(0) + PAGE_SIZE) & ((1 << PMD_SHIFT) - 1));
#else
	WARN_ON((fix_to_virt(0) + PAGE_SIZE) & ((1 << PMD_SHIFT) - 1));

	early_ioremap_setup();

	pmd = early_ioremap_pmd(fix_to_virt(FIX_BTMAP_BEGIN));
	memset(bm_pte, 0, sizeof(bm_pte));
	pmd_populate_kernel(&init_mm, pmd, bm_pte);
    
    ...

	if (pmd != early_ioremap_pmd(fix_to_virt(FIX_BTMAP_END))) {
		WARN_ON(1);
        ...
	}
#endif
```

可以看到，进行了如下操作：

* 定义了`pmd_t`类型的指针，并检查边界是否正确对齐；
* 调用`early_ioremap_setup`填充`512`个临时的固定映射表；
* 获取`pmd`页中间目录项，并设置到内核地址中；
* 检查结束边界，确保在同一`pmd`页表中。

`early_ioremap_setup`在[mm/early_ioremap.c](https://github.com/torvalds/linux/blob/v5.4/mm/early_ioremap.c#L75)实现。将`512`个临时的`fixmap`映射到到8个`slot_virt`中，如下：

```C
void __init early_ioremap_setup(void)
{
	int i;
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		if (WARN_ON(prev_map[i]))
			break;
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		slot_virt[i] = __fix_to_virt(FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*i);
}

...
#define NR_FIX_BTMAPS		64
#define FIX_BTMAPS_SLOTS	8
#define TOTAL_FIX_BTMAPS	(NR_FIX_BTMAPS * FIX_BTMAPS_SLOTS)
```

## 3 设备初始化

### 3.1 获取设备信息

在调用`setup_olpc_ofw_pgd`完成`pgd`设置后，接下来获取设备信息。

* **获取根设备的主次设备号**
  
```C
	ROOT_DEV = old_decode_dev(boot_params.hdr.root_dev);
```

设备的主设备号用来识别和这个设备有关的驱动，次设备号用来表示使用该驱动的各设备。`old_decode_dev`函数从`boot_params`获取了一个参数，从内核引导协议中可以看到：

```C
Field name:    root_dev
Type:        modify (optional)
Offset/size:    0x1fc/2
Protocol:    ALL

  The default root device device number.  The use of this field is
  deprecated, use the "root=" option on the command line instead.
```

`old_decode_dev`在[include/linux/kdev_t.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/kdev_t.h#L34)实现。它根据设备主次设备号调用`MKDEV`宏生成一个`dev_t`类型的设备。

```C
static __always_inline dev_t old_decode_dev(u16 val)
{
	return MKDEV((val >> 8) & 255, val & 255);
}
```

其中`dev_t`是用来表示主/次设备号对的一个内核数据类型。由于历史原因，目前有两种管理主次设备号的方法，第一种方法（old dev）主次设备号占用`16bit`，主设备号占用`8bit`，次设备号占用`8bit`。但是这会引入一个问题：最多只能支持`256`个主设备号和`256`个次设备号。因此后来引入了第二种方法（new dev），使用`32bit`来表示主次设备号，其中主设备号占用`12bit`，次设备号占用`20bit`用来表示，你可以在`new_decode_dev`的实现中找到。

* **获取设备信息**

接下来，从`boot_params`中获取显示器相关参数、扩展显示识别数据、视频模式、BootLoader类型等。必要时获取`apm bios`,`ist bios`,`rd_image`信息，并设置`EFI`相关信息。如下：

```C
	screen_info = boot_params.screen_info;
	edid_info = boot_params.edid_info;
...

#ifdef CONFIG_BLK_DEV_RAM
...
#endif
#ifdef CONFIG_EFI
...
		set_bit(EFI_BOOT, &efi.flags);
		set_bit(EFI_64BIT, &efi.flags);
	}
#endif
```

### 3.2 资源内存映射

* **背景介绍**

在从`boot_params`结构中获取到设备信息后，需要设置`I/O`内存。内核的主要功能是进行资源管理，其中一个资源就是内存。前面我们了解到有两种方式与设备通信（I/O端口和设备内存映射）。有关资源注册的信息可以通过`/proc/ioports`和`/proc/iomem`获取。

* `/proc/ioports` - 提供供设备输入输出的注册端口;
* `/proc/iomem` - 提供每个物理设备的物理内存映射区域；

我们先看下`/proc/iomem`:

```bash
cat /proc/iomem
00000000-00000fff : Reserved
00001000-0009fbff : System RAM
0009fc00-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c99ff : Video ROM
000ca000-000cadff : Adapter ROM
000cb000-000cb5ff : Adapter ROM
000f0000-000fffff : Reserved
  000f0000-000fffff : System ROM
...
240000000-2bfffffff : PCI Bus 0000:00
```

可以看到，根据不同的层次显示十六进制的一段地址区域。Linux内核提供了一种通用的方式来管理这些设备。全局资源（如：PICs或I/O端口）被划分到与硬件总线相关的子集中。在内核中使用`struct resource`来表示：

```C
struct resource {
	resource_size_t start;
	resource_size_t end;
	const char *name;
	unsigned long flags;
	unsigned long desc;
	struct resource *parent, *sibling, *child;
};
```

`struct resource`将系统资源的以树形结构抽象。该结构在[include/linux/ioport.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/ioport.h#L20)中定义，包括：资源占用的起止地址范围、资源名称、标记、描述、树形资源结构指针。

* **iomem_resource**

每个资源子集都有自己个根资源。如：`iomem`资源为`iomem_resource`，在[kernel/resource.c](https://github.com/torvalds/linux/blob/v5.4/kernel/resource.c#L38)中定义，如下：

```C
struct resource iomem_resource = {
	.name	= "PCI mem",
	.start	= 0,
	.end	= -1,
	.flags	= IORESOURCE_MEM,
};
EXPORT_SYMBOL(iomem_resource);
```

`iomem_resource`定义了资源名称（`PCI mem`），开始地址（0），标记（`IORESOURCE_MEM`）。接下来，我们需要设置`iomem_resource`的结束地址，如下：

```C
	iomem_resource.end = (1ULL << boot_cpu_data.x86_phys_bits) - 1;

    ...
	boot_cpu_data.x86_phys_bits = MAX_PHYSMEM_BITS;
```

即，`iomem_resource`可以支持访问最大的内存地址。`iomem_resource`是通过`EXPORT_SYMBOL`宏传递的，这个宏可以把指定的符号（例如`iomem_resource`）做动态链接。换句话说，它可以支持动态加载模块的时候访问对应符号。

* **e820__memory_setup**

接下来，调用`e820__memory_setup`函数实现内存映射。`e820__memory_setup`在[arch/x86/kernel/e820.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/e820.c#L1249)中实现。如下：

```C
void __init e820__memory_setup(void)
{
	char *who;

	/* This is a firmware interface ABI - make sure we don't break it: */
	BUILD_BUG_ON(sizeof(struct boot_e820_entry) != 20);

	who = x86_init.resources.memory_setup();

	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	pr_info("BIOS-provided physical RAM map:\n");
	e820__print_table(who);
}
```

首先，我们来看下`x86_init.resources.memory_setup`。`x86_init`是一种`x86_init_ops`类型的结构体，用来进行资源初始化，`pci`平台特定的一些设置函数等。`x86_init`的初始化实现在[arch/x86/kernel/x86_init.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/x86_init.c#L39)中。如下：

```C
struct x86_init_ops x86_init __initdata = {

	.resources = {
		.probe_roms		= probe_roms,
		.reserve_resources	= reserve_standard_io_resources,
		.memory_setup		= e820__memory_setup_default,
	},
    ...
	.oem = {
		.arch_setup		= x86_init_noop,
		.banner			= default_banner,
	},
    ...
    ...
}
```

可以看到，`x86_init.resources.memory_setup`为`e820__memory_setup_default`，同样在在[arch/x86/kernel/e820.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/e820.c#L1211)中实现。它对在内核启动过程中所有的`E820`信息进行整理，并填充到`e820_table_kexec`和`e820_table_firmware`中，在收集所有的区域后，通过`e820__print_table`输出所有的内存信息。我们可以通过`dmsg`找到类似下面的信息：

```bash
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000bffdcfff] usable
[    0.000000] BIOS-e820: [mem 0x00000000bffdd000-0x00000000bfffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000023fffffff] usable
...
```

* **parse_setup_data**

接下来，调用`parse_setup_data`解析`boot_params.hdr.setup_data`，将存放在其中的不同类型的设备信息（如：[DTB](https://en.wikipedia.org/wiki/Devicetree)、[EFI](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface)、E820_EXT）等。

`setup_data`指向的是一个`struct setup_data`结构的单向链表。如下：

```C
struct setup_data {
	__u64 next;
	__u32 type;
	__u32 len;
	__u8 data[0];
};
```

其中`next`指向下一个节点的物理地址，最后一个节点为0。

### 3.3 复制EDD

调用`copy_edd`函数，复制`boot_params`结构中`EDD`相关信息。如下：

```C
static inline void __init copy_edd(void)
{
     memcpy(edd.mbr_signature, boot_params.edd_mbr_sig_buffer,
	    sizeof(edd.mbr_signature));
     memcpy(edd.edd_info, boot_params.eddbuf, sizeof(edd.edd_info));
     edd.mbr_signature_nr = boot_params.edd_mbr_sig_buf_entries;
     edd.edd_info_nr = boot_params.eddbuf_entries;
}
```

## 4 内存描述符初始化

* **背景介绍**

每个进程都有自己运行的内存地址空间，这个地址空间有个特殊的数据结构叫做`内存描述符（memory descriptor）`。Linux内核中使用`mm_struct`来表示内存描述符，该结构在[include/linux/mm_types.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/mm_types.h#L370)定义。

`mm_struct`包含了许多与进程地址空间有关的字段，如：代码段的起始和结束地址、数据段的起始和结束地址、`brk`的起始和结束地址、内存区域的数量等等。`task_struct`结构中`mm`和`active_mm`字段包含了每个进程自己的内存描述符。 我们的第一个`init_task`进程也有自己的内存描述符，在之前的描述中可以看到初始化信息：

```C
struct task_struct init_task
#ifdef CONFIG_ARCH_TASK_STRUCT_ON_STACK
	__init_task_data
#endif
= {
	...
	.mm		= NULL,
	.active_mm	= &init_mm,
	...
}
```

`mm`表示进程实际的地址空间，`active_mm`表示匿名进程的地址空间，通常指向`init_mm`。在[Documentation/vm/active_mm.rst](https://github.com/torvalds/linux/blob/v5.4/Documentation/vm/active_mm.rst)可以了解更多内容。

`init_mm`是初始化阶段的内存描述符定义，在[mm/init-mm.c](https://github.com/torvalds/linux/blob/v5.4/mm/init-mm.c#L29)定义，如下：

```C
struct mm_struct init_mm = {
	.mm_rb		= RB_ROOT,
	.pgd		= swapper_pg_dir,
	.mm_users	= ATOMIC_INIT(2),
	.mm_count	= ATOMIC_INIT(1),
	.mmap_sem	= __RWSEM_INITIALIZER(init_mm.mmap_sem),
	.page_table_lock =  __SPIN_LOCK_UNLOCKED(init_mm.page_table_lock),
	.arg_lock	=  __SPIN_LOCK_UNLOCKED(init_mm.arg_lock),
	.mmlist		= LIST_HEAD_INIT(init_mm.mmlist),
	.user_ns	= &init_user_ns,
	.cpu_bitmap	= CPU_BITS_NONE,
	INIT_MM_CONTEXT(init_mm)
};
```

* **init_mm段相关初始化**

接下来，我们在初始化阶段完成内存描述发中内核代码段、数据段和`brk`段的初始化：

```C
	if (!boot_params.hdr.root_flags)
		root_mountflags &= ~MS_RDONLY;
	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code = (unsigned long) _etext;
	init_mm.end_data = (unsigned long) _edata;
	init_mm.brk = _brk_end;
```

* **内存扩展保护初始化`mpx_mm_init`**

`mpx_mm_init`在[arch/x86/include/asm/mpx.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/mpx.h#L76)定义。

* **段资源初始化**

接下来，进行代码段、数据段、`bss`段资源的初始化。

```C
	code_resource.start = __pa_symbol(_text);
	code_resource.end = __pa_symbol(_etext)-1;
	data_resource.start = __pa_symbol(_etext);
	data_resource.end = __pa_symbol(_edata)-1;
	bss_resource.start = __pa_symbol(__bss_start);
	bss_resource.end = __pa_symbol(__bss_stop)-1;

	...
static struct resource data_resource = {
	.name	= "Kernel data",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM
};
```

在上一部分中，我们对`resource`进行了描述。现在，我们把数据段、代码段、`bss`段资源的初始化，在`/proc/iomem`可以看到：

```bash
00100000-bffdcfff : System RAM
  01000000-01e00e70 : Kernel code
  01e00e71-0284cc7f : Kernel data
  02b17000-02ffffff : Kernel bss
```

## 5 解析早期参数

### 5.1 命令行初始化

接下来，根据不同的配置选项，获取`boot_command_line`，`builtin_cmdline`，并最终初始化`command_line`。如下：

```C
	strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = command_line;
```

`cmdline_p`为`setup_arch(&command_line)`的入参，现在进行了赋值。

### 5.2 NX位设置（`x86_configure_nx`）

`NX-bit`或者`no-execute`位是页目录条目的第`63`比特位，它的作用是控制被映射的物理页面是否具有执行代码的能力。只有在`EFER.NXE`置为1（使能）的情况下，即，`no-execute`页保护机制开启的情况下，才能被使用或设置。

`x86_configure_nx`函数在[arch/x86/mm/setup_nx.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/setup_nx.c#L34)中实现。该函数会检查CPU是否支持`NX-bit`，以及是否被禁用。在检查后，我们把结果赋值给`_supported_pte_mask`。

```C
void x86_configure_nx(void)
{
	if (boot_cpu_has(X86_FEATURE_NX) && !disable_nx)
		__supported_pte_mask |= _PAGE_NX;
	else
		__supported_pte_mask &= ~_PAGE_NX;
}
```

### 5.3 解析早期参数（`parse_early_param`）

* **背景介绍**

根据名称我们可以了解到，这个函数解析命令行参数，并基于给定的参数创建不同的服务。所有的内核命令行参数可以在[Documentation/admin-guide/kernel-parameters.txt](https://github.com/torvalds/linux/blob/v5.4/Documentation/admin-guide/kernel-parameters.txt)找到。

在前面的章节中，我们在初始化`earlyprintk`时用[arch/x86/boot/cmdline.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/cmdline.c)中的`__cmdline_find_option`, `__cmdline_find_option_bool`函数寻找内核参数及值。现在，我们在通用内核部分，不依赖特定的系统架构，这里使用另一种方法。

在查看Linux内核源代码时，你可能会注意到这样的调用：

```C
early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);
```

`parse_early_param`正是解析命令行参数，并对`early_param`相关函数调用的。`early_param`宏需要两个参数，即：`命令行参数的名称`和`调用函数`。该宏在[include/linux/init.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/init.h#L268)定义，如下：

```C
struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst		\
		__aligned(1) = str; 					\
	static struct obs_kernel_param __setup_##unique_id		\
		__used __section(.init.setup)				\
		__attribute__((aligned((sizeof(long)))))		\
		= { __setup_str_##unique_id, fn, early }

#define __setup(str, fn)						\
	__setup_param(str, fn, fn, 0)

#define early_param(str, fn)						\
	__setup_param(str, fn, fn, 1)
```

可以看到，`early_param`只是调用`__setup_param`。而`__setup_param`在内部根据`unique_id`(即函数名称）创建了`obs_kernel_param`类型的变量，并将其存放在`__section(.init.setup)`段。在[include/asm-generic/vmlinux.lds.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/vmlinux.lds.h#L795)可以看到，`.init.setup`段被放置在 `__setup_start`和`__setup_end`之间，如下：

```C
#define INIT_SETUP(initsetup_align)					\
		. = ALIGN(initsetup_align);				\
		__setup_start = .;					\
		KEEP(*(.init.setup))					\
		__setup_end = .;
```

* **实现过程**

`parse_early_param`在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L480)实现。如下：

```C
/* Check for early params. */
static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;
	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	//parse_args("early options", cmdline, NULL, 0, 0, 0, NULL, do_early_param);
	done = 1;
}
```

`parse_early_param`函数主要过程如下：

* 在内部定义了两个静态变量，`done`用来检查该函数是否已经调用过，`tmp_cmdline`用来存放临时存放命令行；
* 在对`tmp_cmdline`赋值后，调用同文件中`parse_early_options`函数。`parse_early_options`调用[kernel/params.c](https://github.com/torvalds/linux/blob/v5.4/kernel/params.c#L161)中的`parse_args`函数；
* `parse_args`解析命令参数，并调用`do_early_param`函数；
* `do_early_param`从`__setup_start`循环到`__setup_end`，逐个判断`obs_kernel_param`实例中的`early`和`str`字段，符合时，调用`setup_func`进行对应的操作。

### 5.4 打印NX信息（`x86_report_nx`）

`x86_report_nx`函数在[arch/x86/mm/setup_nx.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/setup_nx.c#L42)中实现。该函数打印有关NX的提示信息。

在上面我们调用了`x86_configure_nx`配置了NX位。值得注意的是，`x86_report_nx`函数不一定在`x86_configure_nx`函数之后调用，但是一定在`parse_early_param`之后调用。答案很简单: 因为内核支持`noexec`参数，所以我们一定在`parse_early_param`调用并且解析`noexec`参数之后才能调用`x86_report_nx`。`x86_report_nx`的输出信息如下：

```bash
[    0.000000] NX (Execute Disable) protection: active
[    0.000000] SMBIOS 2.8 present.
```

## 6 内存解析完成

接下来，这部分涉及到`memblock`和`e820`相关的函数，包括：

```C
	memblock_x86_reserve_range_setup_data();
	e820__reserve_setup_data();
	e820__finish_early_params();

	...
	e820_add_kernel_range();
	trim_bios_range();
	max_pfn = e820__end_of_ram_pfn();
	max_low_pfn = e820__end_of_low_ram_pfn();
```

* `memblock_x86_reserve_range_setup_data`
  
将`setup_data`段进行重新映射并保留内存块。

* `e820__reserve_setup_data`
  
功能同`memblock_x86_reserve_range_setup_data`类似，除了重新映射之外，还会调用`e820__range_update`更新`e820_table`和`e820_table_kexec`的映射区域。

* `e820__finish_early_params`

`e820`中可以通过`mem`和`memmap`这两个`early_param`更新`e820_table`。这里在通过`memmap`选项配置后，重新更新`e820_table`，并输出内存信息。
  
* `e820_add_kernel_range`
  
将`_text`到`_end`之间的物理内存区域进行映射。如果`.text`、`.data`、`.bss`这几个段没有被标记为`E820_TYPE_RAM`，输出提示信息后，重新映射。

* `trim_bios_range`
  
将前4KB内存标记为`E820_TYPE_RESERVED`；如果BIOS区域（640->1MB）是RAM时，释放该区域；并更新`e820_table`。

* `e820__end_of_ram_pfn`
  
获取最后最后一个内存页的的编号，每个内存页都有唯一的编号(页帧号，page frame number)。PFN通过`entry->addr >> PAGE_SHIFT`计算得到的，因此，最大的页帧标号（`MAX_ARCH_PFN`）在`x86_64`定义为`MAXMEM>>PAGE_SHIFT`，即，`0x400000000`(4级页表的情况下)。

在`dmesg`的输出中可以看到`last_pfn`:

```text
[    0.028861] last_pfn = 0x240000 max_arch_pfn = 0x400000000
```

* `e820__end_of_low_ram_pfn`

获取低端内存（或4GB内存）的页帧编号。

## 7 建立设备树

### 7.1 桌面管理接口设置（DMI）

接下来，调用`dmi_setup`函数，收集[桌面管理接口（DMI，Desktop Management Interface）](https://en.wikipedia.org/wiki/Desktop_Management_Interface)信息。

`dmi_setup`函数在[drivers/firmware/dmi_scan.c](https://github.com/torvalds/linux/blob/v5.4/drivers/firmware/dmi_scan.c#L777)实现，如下：

```C
void __init dmi_setup(void)
{
	dmi_scan_machine();
	if (!dmi_available)
		return;

	dmi_memdev_walk();
	dump_stack_set_arch_desc("%s", dmi_ids_string);
}
```

* **dmi_scan_machine**

`dmi_scan_machine`函数遍历[SMBIOS, System Management BIOS](https://en.wikipedia.org/wiki/System_Management_BIOS)结构，并提取信息。目前有两种方式来访问`SMBIOS`表：第一种方式从EFI配置表中获取`SMBIOS`的地址；第二种方式是扫描`0xF0000~0x10000`之间的物理内存。两种方式获取DMI的方式类似，均是从iomap区域读取内存后，对读取的内存调用`dmi_smbios3_present`和`dmi_present`。这两个函数检查内存是否以`_SM3_`或`_SM_`开始的字符串，并获取`SMBIOS`的版本和`_DMI_`的属性（如`_DMI_`版本、数量、地址等）。在`dmesg`中可以看到相关信息：

```bash
[    0.000000] SMBIOS 2.8 present.
[    0.000000] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 0
```

* **dmi_memdev_walk**

该函数定义实现如下：

```C
static void __init dmi_memdev_walk(void)
{
	if (dmi_walk_early(count_mem_devices) == 0 && dmi_memdev_nr) {
		dmi_memdev = dmi_alloc(sizeof(*dmi_memdev) * dmi_memdev_nr);
		if (dmi_memdev)
			dmi_walk_early(save_mem_devices);
	}
}

...
static int __init dmi_walk_early(void (*decode)(const struct dmi_header *,
		void *))
{
	...
}
```

`dmi_walk_early`函数有一个参数，是个回调函数。在逐个遍历`DMI`信息后，进行回调操作。

`dmi_memdev_walk`函数通过`dmi_walk_early`函数收集内存设备的相关信息。`count_mem_devices`累加`dmi_memdev_nr`的值，`save_mem_devices`将`dmi_header`转换为`dmi_memdev_info`，`dmi_decode`解析`dmi_header`。

### 7.2 虚拟机管理器初始化（`init_hypervisor_platform`）

[Hypervisor](https://en.wikipedia.org/wiki/Hypervisor)是一种虚拟化技术。`init_hypervisor_platform`函数在[arch/x86/kernel/cpu/hypervisor.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/hypervisor.c#L95)实现。

```C
void __init init_hypervisor_platform(void)
{
	const struct hypervisor_x86 *h;
	h = detect_hypervisor_vendor();
	if (!h)
		return;
	copy_array(&h->init, &x86_init.hyper, sizeof(h->init));
	copy_array(&h->runtime, &x86_platform.hyper, sizeof(h->runtime));
	x86_hyper_type = h->type;
	x86_init.hyper.init_platform();
}
```

`init_hypervisor_platform`函数通过`detect_hypervisor_vendor`获取`hypervisor_x86`后，将相关信息复制到`x86_init.hyper`和`x86_platform.hyper`，最后调用`x86_init.hyper.init_platform`初始化虚拟机平台。

目前，支持的虚拟化平台定义如下：

```C
static const __initconst struct hypervisor_x86 * const hypervisors[] =
{
	&x86_hyper_xen_pv, //"Xen PV"
	&x86_hyper_xen_hvm, //"Xen HVM"
	&x86_hyper_vmware, //"VMware"
	&x86_hyper_ms_hyperv, //"Microsoft Hyper-V"
	&x86_hyper_kvm, //"KVM"
	&x86_hyper_jailhouse, //"Jailhouse"
	&x86_hyper_acrn, //"ACRN"
};
```

### 7.3 时间戳计数器早期初始化（`tsc_early_init`）

[时间戳计数器(TSC, Time Stamp Counter)](https://en.wikipedia.org/wiki/Time_Stamp_Counter)记录CPU复位后的周期数。

`tsc_early_init`函数在[arch/x86/kernel/tsc.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/tsc.c#L1455)中实现。

该函数校准CPU，获取CPU的周期频率，计算`loops_per_jiffy`。在`dmesg`可以看出如下信息：

```bash
[    0.000000] tsc: Fast TSC calibration using PIT
[    0.000000] tsc: Detected 2592.073 MHz processor
```

### 7.4 建立iomem资源树

在前面，对`iomem_resource`进行了描述。我们字段`resource`是一个树形结构，通过`parent`,`sibling`,`child`这三个形成树形结构，如下：

```text
+-------------+
|    parent   |
+-------------+
       |
+-------------+      +-------------+
|    current  |------|    sibling  |
+-------------+      +-------------+
       |
+-------------+
|    child    | 
+-------------+
```

接下来，构建`iomem_resource`下面的资源组织结构。如下：

```C
x86_init.resources.probe_roms();
insert_resource(&iomem_resource, &code_resource);
insert_resource(&iomem_resource, &data_resource);
insert_resource(&iomem_resource, &bss_resource);
```

`x86_init.resources.probe_roms();`定义为`probe_roms`，在[arch/x86/kernel/probe_roms.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/probe_roms.c#L198)中实现。将`system_rom_resource`,`extension_rom_resource`,`adapter_rom_resources`,`video_rom_resource`逐个调用`request_resource`函数挂载在`iomem_resource`下。

`request_resource`和`insert_resource`函数都在[kernel/resource.c](https://github.com/torvalds/linux/blob/v5.4/kernel/resource.c#L866)中实现。`insert_resource`函数执行过程中会调用`request_resource`。

### 7.5 早期GART内存检查（`early_gart_iommu_check`）

[GART(Graphics address remapping table)](https://en.wikipedia.org/wiki/Graphics_address_remapping_table)是供APG和PCIe显卡使用的IO内存管理单元。

`early_gart_iommu_check`函数在[arch/x86/kernel/aperture_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/aperture_64.c#L288)中实现。

其中`search_agp_bridge`函数遍历PCI信息，每个PCI域可以承载多达`256`条总线，并且每条总线可以承载多达`32`个设备，依次读取`read_pci_config`。如下：

```C
	for (bus = 0; bus < 256; bus++) {
		for (slot = 0; slot < 32; slot++) {
			for (func = 0; func < 8; func++) {
				class = read_pci_config(bus, slot, func, PCI_CLASS_REVISION);
			}
		}
	}
```

## 8 均衡多处理器配置（`find_smp_config`）

接下来是解析[SMP(Symmetric multiprocessing)](https://en.wikipedia.org/wiki/Symmetric_multiprocessing)的配置信息。`find_smp_config`函数的实现如下:

```C
static inline void find_smp_config(void)
{
        x86_init.mpparse.find_smp_config();
}

//arch/x86/kernel/x86_init.c
.find_smp_config = default_find_smp_config,
```

在函数的内部，`x86_init.mpparse.find_smp_config`函数即[arch/x86/kernel/mpparse.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/mpparse.c#L619)中的`default_find_smp_config`函数。`default_find_smp_config`函数从内存中的`最低的1K`、`基础内存（640K）的最后1K`、`bios中的64K`的区域来寻找`SMP`的配置信息，并在找到它们的时候返回:

```C
	if (smp_scan_config(0x0, 0x400) ||
	    smp_scan_config(639 * 0x400, 0x400) ||
	    smp_scan_config(0xF0000, 0x10000))
		return;
```

`smp_scan_config`函数在指定的内存区域中循环查找`MP floating pointer structure`，这个结构定义为`struct mpf_intel`。通过检查当前字节是否指向`SMP`签名(`_MP_`)，检查签名的校验和，并且检查标准版本号值(这个值只能是1或者4)。`struct mpf_intel`定义如下：

```C
struct mpf_intel {
        char signature[4];
        unsigned int physptr;
        unsigned char length;
        unsigned char specification;
        unsigned char checksum;
        unsigned char feature1;
        unsigned char feature2;
        unsigned char feature3;
        unsigned char feature4;
        unsigned char feature5;
};
```

如果搜索成功，就调用`memblock_reserve`函数保留该区域内存，并为多处理器配置表保留物理地址。

## 9 保留内存区域设置

* **分配页表内存(`early_alloc_pgt_buf`)**

下一步，我们可以看到`early_alloc_pgt_buf`函数的调用，这个函数在早期阶段分配页表缓冲区。页表缓冲区将被放置在`brk`段中。如下：

```C
#ifndef CONFIG_RANDOMIZE_MEMORY
#define INIT_PGD_PAGE_COUNT      6
#else
#define INIT_PGD_PAGE_COUNT      12
#endif
#define INIT_PGT_BUF_SIZE	(INIT_PGD_PAGE_COUNT * PAGE_SIZE)
RESERVE_BRK(early_pgt_alloc, INIT_PGT_BUF_SIZE);
void  __init early_alloc_pgt_buf(void)
{
        unsigned long tables = INIT_PGT_BUF_SIZE;
        phys_addr_t base;

        base = __pa(extend_brk(tables, PAGE_SIZE));

        pgt_buf_start = base >> PAGE_SHIFT;
        pgt_buf_end = pgt_buf_start;
        pgt_buf_top = pgt_buf_start + (tables >> PAGE_SHIFT);
}
```

首先这个函数获得页表缓冲区的大小（即：`INIT_PGT_BUF_SIZE`），这个值为`6 * PAGE_SIZE`或`12 * PAGE_SIZE`（在开启地址随机化选项的情况下）。我们得到了页表缓冲区的大小后，调用`extend_brk`函数扩展`brk`区域。`extend_brk`需要传入两个参数: `size`和`align`。在linux内核链接脚本中看到`brk`区段在内存中的位置就在`BSS`区段后面:

```C
	. = ALIGN(PAGE_SIZE);
	.brk : AT(ADDR(.brk) - LOAD_OFFSET) {
		__brk_base = .;
		. += 64 * 1024;		/* 64k alignment slop space */
		*(.brk_reservation)	/* areas brk users have reserved */
		__brk_limit = .;
	}
```

我们也可以使用`readelf`工具来找到它:

```bash
#x86_64-elf-readelf  -S
  [58] .bss              NOBITS           ffffffff82b17000  01f17000
       00000000004e9000  0000000000000000  WA       0     0     4096
  [59] .brk              NOBITS           ffffffff83000000  01f17000
       000000000002c000  0000000000000000  WA       0     0     1
```

之后我们用`_pa`宏得到了新的`brk`区段的物理地址，并计算页表缓冲区的基地址和结束地址。

* **保留`brk`段内存(`reserve_brk`)**

接下来，我们调用`reserve_brk`函数将`brk`区段设置为保留内存块:

```C
static void __init reserve_brk(void)
{
	if (_brk_end > _brk_start)
		memblock_reserve(__pa_symbol(_brk_start),
				 _brk_end - _brk_start);

	_brk_start = 0;
}
```

注意在`reserve_brk`的最后，我们把`_brk_start`赋值为0，因为在这之后我们不会再为`brk`分配内存了。

* **清理高映射内存(`cleanup_highmap`)**

我们需要使用`cleanup_highmap`函数来释放内核映射中越界的内存区域。内核映射是`__START_KERNEL_map`到`__START_KERNEL_map + size`区间的内存，(其中，`size = _end - _text`) 或者`level2_kernel_pgt`对内核`code`、`data`和`bss`区段的映射。`clean_high_map`函数在[arch/x86/mm/init_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/init_64.c#L420)中实现，如下：

```C
	unsigned long vaddr = __START_KERNEL_map;
	unsigned long vaddr_end = __START_KERNEL_map + KERNEL_IMAGE_SIZE;
	unsigned long end = roundup((unsigned long)_brk_end, PMD_SIZE) - 1;
	pmd_t *pmd = level2_kernel_pgt;

	if (max_pfn_mapped)
		vaddr_end = __START_KERNEL_map + (max_pfn_mapped << PAGE_SHIFT);

	for (; vaddr + PMD_SIZE - 1 < vaddr_end; pmd++, vaddr += PMD_SIZE) {
		if (pmd_none(*pmd))
			continue;
		if (vaddr < (unsigned long) _text || vaddr > end)
			set_pmd(pmd, __pmd(0));
	}
```

检查内核映射的开始和结束位置，循环遍历所有内核页中间目录条目, 并且清除不在`_text`和`end`区段中的PMD目录项。

* **限制memblock大小(`memblock_set_current_limit`)**

在这之后，我们使用`memblock_set_current_limit`函数来为`memblock`分配内存设置一个界限。这个界限可以是`ISA_END_ADDRESS(0x00100000)。

* **填充e820到memblock(`e820__memblock_setup`)**

然后调用`e820__memblock_setup`函数将`e820_table`里的内存信息填充到`memblock`中。在命令行里有`memblock=debug`参数时，可以在`dmesg`中看到以下类似信息:

```bash
MEMBLOCK configuration:
 memory size = 0x1fff7ec00 reserved size = 0x1e30000
 memory.cnt  = 0x3
 memory[0x0]	[0x00000000001000-0x0000000009efff], 0x9e000 bytes flags: 0x0
 memory[0x1]	[0x00000000100000-0x000000bffdffff], 0xbfee0000 bytes flags: 0x0
 memory[0x2]	[0x00000100000000-0x0000023fffffff], 0x140000000 bytes flags: 0x0
 reserved.cnt  = 0x3
 reserved[0x0]	[0x0000000009f000-0x000000000fffff], 0x61000 bytes flags: 0x0
 reserved[0x1]	[0x00000001000000-0x00000001a57fff], 0xa58000 bytes flags: 0x0
 reserved[0x2]	[0x0000007ec89000-0x0000007fffffff], 0x1377000 bytes flags: 0x0
```

* **`reserve_ibft_region`**

`reserve_ibft_region`函数用来寻找ibft(iSCSI Boot Format Table)区域，存在相关区域后保留该区域内存。该区域在`IBFT_START(0x80000， 512K)`和`IBFT_END(0x100000, 1MB)`之间，但需要避开VGA区域（`0xA0000 ~ 0xC0000`）。在[drivers/firmware/iscsi_ibft_find.c](https://github.com/torvalds/linux/blob/v5.4/drivers/firmware/iscsi_ibft_find.c)实现该区域的查找。

* **`reserve_bios_regions`**

`reserve_bios_regions`函数保留系统BIOS固件内存区域。在[arch/x86/kernel/ebda.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/ebda.c#L56)中实现。

* **`early_reserve_e820_mpc_new`**

`early_reserve_e820_mpc_new`函数在`e820_table_kexec`中为多处理器规格表分配额外的内存。在[arch/x86/kernel/mpparse.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/mpparse.c#L848)中实现。

* **`reserve_real_mode`**

`reserve_real_mode`函数保留从`0x0 ~ 1M`的低端内存用作到实模式的跳板(用于重启等...)。在[arch/x86/realmode/init.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/realmode/init.c#L18)中实现。

* **`trim_platform_memory_ranges`**

`trim_platform_memory_ranges`函数用于清除掉以`0x20050000`,`0x20110000`,`0x20130000`,`0x20138000`,`0x40004000`等地址开头的内存空间。`Sandy Bridge graphics`在这些内存区域出现一些问题。在`arch/x86/kernel/setup.c`文件中实现。

* **`trim_low_memory_range`**

`trim_low_memory_range`函数保留`memblock`中的前`4KB~64KB`大小内存。大小可通过`reservelow`参数设置，默认64KB。在`arch/x86/kernel/setup.c`文件中实现。

* **`init_mem_mapping`**
  
`init_mem_mapping`函数用于在`PAGE_OFFSET`处重建物理内存(`0 ~ max_pfn << PAGE_SHIFT`)的直接映射，在命令行传入`memtest`的参数时，测试内存。在[arch/x86/mm/init.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/init.c#L649)中实现。

* **`early_trap_pf_init`**

`early_trap_pf_init`函数用于建立`#PF`的中断处理函数。在[arch/x86/kernel/idt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/idt.c#L279)中实现。

* **更新`mmu_cr4_features`**

接下来，使用当前CR4寄存器值更新`mmu_cr4_features`（并且间接的更新`trampoline_cr4_features`）。

```C
	mmu_cr4_features = __read_cr4() & ~X86_CR4_PCIDE;
```

## 10 设置日志缓冲区（`setup_log_buf`）

`setup_log_buf`函数在[kernel/printk/printk.c](https://github.com/torvalds/linux/blob/v5.4/kernel/printk/printk.c#L1149)中实现。它设置内核日志循环缓冲区，其大小取决于`CONFIG_LOG_BUF_SHIFT`的配置。在内核中，日志缓冲区的定义如下：

```C
#define LOG_ALIGN __alignof__(struct printk_log)
#define __LOG_BUF_LEN (1 << CONFIG_LOG_BUF_SHIFT)
#define LOG_BUF_LEN_MAX (u32)(1 << 31)
static char __log_buf[__LOG_BUF_LEN] __aligned(LOG_ALIGN);
static char *log_buf = __log_buf;
static u32 log_buf_len = __LOG_BUF_LEN;
```

`setup_log_buf`函数有一个参数，标识是否为早期设置。第一次调用时是早期设置，后续调用时分配`precpu`区域。具体实现过程为：首先检查当前缓冲区是否为空，是否为早期设置等，不是早期设置，调用`log_buf_add_cpu`为每个CPU增加缓冲区大小；接下来，检查`new_log_buf_len`大小(根据命令行参数`log_buf_len`计算)，更新内核缓冲区的大小，必要时调用`memblock_alloc`分配新的缓冲区。

## 11 保留initrd（`reserve_initrd`）

在前面我们调用`early_reserve_initrd`保留了`initrd`镜像区域，并通过`init_mem_mapping`重建了直接内存映射。现在调用`reserve_initrd`函数将`initrd`移动到直接映射内存。

`reserve_initrd`函数主要执行过程如下：

* 必要的检查

获取`initrd`的镜像地址和大小，计算`memblock`映射内存的大小。在映射内存不足时，调用[Kernel panic](https://en.wikipedia.org/wiki/Kernel_panic)函数，打印panic信息。

```C
	mapped_size = memblock_mem_size(max_pfn_mapped);
	if (ramdisk_size >= (mapped_size>>1))
		panic("initrd too large to handle, "
		       "disabling initrd (%lld needed, %lld available)\n",
		       ramdisk_size, mapped_size>>1);
```

* 映射`initrd`

调用`pfn_range_is_mapped`检查`initrd`区域是否已经映射。如果已经映射了，重新设置`initrd_start`和`initrd_end`的位置。否则，调用`relocate_initrd`进行重新映射。`relocate_initrd`调用`memblock_find_in_range`查找直接映射区域，没找符合大小的区域是，进入`panic`。正常情况下，调用`copy_from_early_mem`从`ioremem`区域移动到重新映射区域。

* 释放映射`memblock`内存

在`relocate_initrd`映射后，调用`memblock_free`释放`early_reserve_initrd`预留的内存。

## 12 ACPI相关初始化

### 12.1 ACPI初始化

接下来，进行[ACPI(Advanced Configuration and Power Interface)](https://en.wikipedia.org/wiki/Advanced_Configuration_and_Power_Interface)初始化。

首先，调用`acpi_table_upgrade`函数从固件内存中查找对应的文件信息，并填充`acpi_initrd_files`，在[drivers/acpi/tables.c](https://github.com/torvalds/linux/blob/v5.4/drivers/acpi/tables.c#L514)中实现。之后，调用`acpi_boot_table_init`初始化`initial_tables`，并保留相关区域内存。

存在ACPI信息是，在`dmesg`中可以找到如下信息：

```bash
[    0.065291] ACPI: Early table checksum verification disabled
[    0.066126] ACPI: RSDP 0x00000000000F5A20 000014 (v00 BOCHS )
...
[    0.069098] ACPI: Reserving FACP table memory at [mem 0xbffe15ff-0xbffe1672]
[    0.069141] ACPI: Reserving DSDT table memory at [mem 0xbffdfd80-0xbffe15fe]
[    0.069155] ACPI: Reserving FACS table memory at [mem 0xbffdfd40-0xbffdfd7f]
...
```

### 12.2 VSMP初始化（`vsmp_init`）

`vsmp_init`函数实现`ScaleMP vSMP`系统的初始化。在[arch/x86/kernel/vsmp_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/vsmp_64.c#L141)中实现。

### 12.3 IO延时初始化（`io_delay_init`)

`io_delay_init`函数运行我们重新设置默认的I/O延时端口（即，0x80）。我们在启动阶段进入保护模式前，设置过`io_delay`。接下来，我们看下其实现过程。`io_delay_init`函数在[arch/x86/kernel/io_delay.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/io_delay.c#L122)中实现。如下：

```C
void __init io_delay_init(void)
{
	if (!io_delay_override)
		dmi_check_system(io_delay_0xed_port_dmi_table);
}
```

在判断`io_delay_override`变量允许时进行I/O延时端口设置。`io_delay_override`通过命令行`io_delay`选项设置（即，通过`early_param("io_delay", io_delay_param)`参数），`io_delay`选项包括：

```bash
io_delay=    [X86] I/O delay method
    0x80
        Standard port 0x80 based delay
    0xed
        Alternate port 0xed based delay (needed on some systems)
    udelay
        Simple two microseconds delay
    none
        No delay
```

`dmi_check_system`函数检查`io_delay_0xed_port_dmi_table`中DMI设备，并通过`dmi_io_delay_0xed_port`回调函数将其I/O端口设置为`0xed`。`dmi_check_system`函数在[drivers/firmware/dmi_scan.c](https://github.com/torvalds/linux/blob/v5.4/drivers/firmware/dmi_scan.c#L849)中实现。

### 12.4 早期ACPI启动初始化（`early_acpi_boot_init`)

`early_acpi_boot_init`函数在[arch/x86/kernel/acpi/boot.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/acpi/boot.c#L1577)中实现。

在检查`acpi_disabled`参数设置后；调用`acpi_table_init_complete`初始化所有的`initial_tables`，并检查`Multiple APIC Description Table (MADT)`；然后，调用`acpi_table_parse`函数解析`ACPI_SIG_BOOT`表；接下来，调用`acpi_blacklisted`判断是否在黑名单里，并根据`acpi=force`判断是禁用`acpi`还是强制使用；接下来，在存在`madt`的情况下，调用`early_acpi_process_madt`函数处理；最后，调用`acpi_reduced_hw_init`进行硬件初始化。

可通过`early_param("acpi", parse_acpi);`进行`acpi`相关设置；

## 13 硬件访问相关内存设置

### 13.1 NUMA内存初始化（`initmem_init`)

`initmem_init`函数在[arch/x86/mm/numa_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/numa_64.c#L10)中实现，直接调用`x86_numa_init`函数。`x86_numa_init`函数在[arch/x86/mm/numa.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/numa.c#L705)中实现。进行[非统一内存访问(UNMA,Non-uniform memory access)](https://en.wikipedia.org/wiki/Non-uniform_memory_access)初始化。

### 13.2 分配DMA区域（`dma_contiguous_reserve`）

接下来，我们需要调用`dma_contiguous_reserve`函数分配[直接内存访问(DMA,Direct memory access)](http://en.wikipedia.org/wiki/Direct_memory_access)内存区域。`dma_contiguous_reserve`函数在[kernel/dma/contiguous.c](https://github.com/torvalds/linux/blob/v5.4/kernel/dma/contiguous.c#L107)中实现。

DMA是设备不通过CPU直接访问内存的特殊模式，`dma_contiguous_reserve`函数需要一个参数，即：保留内存的限制。实现如下：

```C
	phys_addr_t selected_size = 0;
	phys_addr_t selected_base = 0;
	phys_addr_t selected_limit = limit;
	bool fixed = false;
	...
	if (size_cmdline != -1) {
		...
	} else {
		...
	}
	
	if (selected_size && !dma_contiguous_default_area) {
		...
		dma_contiguous_reserve_area(selected_size, selected_base,
					    selected_limit,
					    &dma_contiguous_default_area,
					    fixed);
	}
```

首先，定义变量，`selected_size`表示保留区大小，`selected_base`表示保留区的基地址，`selected_limit`表示保留区的结束地址，`fixed`表示保留区存放的位置。`fixed = true`表示我们只使用`memblock_reserve`的保留区域，否则，使用`memblock_phys_alloc_range`分配内存。

接下来，检查`size_cmdline`大小，判断使用内核默认设置还是通过`cma`命令行参数。通过`early_param("cma", early_cma);`早期参数可设置保留区间，参数为`cma=nn[MG]@[start[MG][-end[MG]]]`。如果没有设置`cma`参数，则使用系统配置选项，配置选项包括以下选项：

* `CONFIG_CMA_SIZE_SEL_MBYTES` - MB大小, 默认的全局CAM区域，大小为 `CMA_SIZE_MBYTES * SZ_1M` 或者 `CONFIG_CMA_SIZE_MBYTES * 1M`；
* `CONFIG_CMA_SIZE_SEL_PERCENTAGE` - 占所有内存的比例；
* `CONFIG_CMA_SIZE_SEL_MIN` - 使用默认值和比例值之间的较小值；
* `CONFIG_CMA_SIZE_SEL_MAX` - 使用默认值和比例值之间的较大值；

在计算保留区域的大小后，我们通过调用`dma_contiguous_reserve_area`函数保留该区域内存。`dma_contiguous_reserve_area`函数根据基地址和大小保留连续的内存区域。

在后面，通过`memblock_find_dma_reserve`函数计算DMA区域的大小。

### 13.3 稀疏内存初始化

接下来，我们调用`x86_init.paging.pagetable_init();`函数。`pagetable_init`值为`native_pagetable_init`，而`native_pagetable_init`是个宏定义，定义为`paging_init`。`paging_init`在[arch/x86/mm/init_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/init_64.c#L809)中实现。

`paging_init`函数初始化稀疏内存（sparse memory）的区域大小。稀疏内存是Linux内核中内存管理的一个特殊的基础，它在NUMA系统中即将内存区域分成不同的内存库。实现如下：

```C
void __init paging_init(void)
{
	sparse_memory_present_with_active_regions(MAX_NUMNODES);
	sparse_init();

	node_clear_state(0, N_MEMORY);
	if (N_MEMORY != N_NORMAL_MEMORY)
		node_clear_state(0, N_NORMAL_MEMORY);

	zone_sizes_init();
}
```

首先，我们调用`sparse_memory_present_with_active_regions`函数记录每个NUMA节点内存区域到`mem_section`结构数组里，`mem_section`结构数组包括指向`struct page`的指针；`sparse_memory_present_with_active_regions`函数在[mm/page_alloc.c](https://github.com/torvalds/linux/blob/v5.4/mm/page_alloc.c#L6289)中实现；
接下来，调用`sparse_init`函数分配非线性区域段（`mem_section`），并为每个段分配`mem_map`记录物理地址的映射；`sparse_init`函数在[mm/sparse.c](https://github.com/torvalds/linux/blob/v5.4/mm/sparse.c#L579)中实现；
接下来，调用`node_clear_state`清除节点状态，
最后，`zone_sizes_init`函数初始化区（zone）的大小；每个`NUMA`节点都被划分成若干块，每块称为区（zone）；`zone_sizes_init`函数在[arch/x86/mm/init.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/init.c#L934)中实现。

## 14 映射vsyscall

[虚拟系统调用(vsyscall, virtual system call)](https://lwn.net/Articles/446528/)是一种特殊的系统调用，不需要任何特殊的特级权限即可运行。如`gettimeofday()`，它所做的就是读取内核当前时间，内存运行将当前时间的内存页以只读方式映射到用户空间。使用`vsyscall`时，可以不用切换到内核空间。

`map_vsyscall`函数映射`vsyscall`的内存空间，在[arch/x86/entry/vsyscall/vsyscall_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/vsyscall/vsyscall_64.c#L376)中实现。如下：

```C
void __init map_vsyscall(void)
{
	extern char __vsyscall_page;
	unsigned long physaddr_vsyscall = __pa_symbol(&__vsyscall_page);

	if (vsyscall_mode == EMULATE) {
		__set_fixmap(VSYSCALL_PAGE, physaddr_vsyscall,
			     PAGE_KERNEL_VVAR);
		set_vsyscall_pgtable_user_bits(swapper_pg_dir);
	}

	if (vsyscall_mode == XONLY)
		gate_vma.vm_flags = VM_EXEC;

	BUILD_BUG_ON((unsigned long)__fix_to_virt(VSYSCALL_PAGE) !=
		     (unsigned long)VSYSCALL_ADDR);
}
```

在函数的开始，我们定义了两个变量。第一个变量是`extern char __vsyscall_page`，作为一个外部变量，在其他的源代码文件中定义，我们在[arch/x86/entry/vsyscall/vsyscall_emu_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/vsyscall/vsyscall_emu_64.S#L15)找到了其定义。`__vsyscall_page`符号指向`gettimeofday`之类`vsyscalls`的对齐页。定义如下：

```C
__PAGE_ALIGNED_DATA
	.globl __vsyscall_page
	.balign PAGE_SIZE, 0xcc
	.type __vsyscall_page, @object
__vsyscall_page:

	mov $__NR_gettimeofday, %rax
	syscall
	ret

	.balign 1024, 0xcc
	mov $__NR_time, %rax
	syscall
	ret

	.balign 1024, 0xcc
	mov $__NR_getcpu, %rax
	syscall
	ret

	.balign 4096, 0xcc

	.size __vsyscall_page, 4096
```

第二个变量是`physaddr_vsyscall`指向`__vsyscall_page`变量的物理内存。接下来，我们检查`vsyscall_mode`变量，它支持三种不同的设置`EMULATE, XONLY, NONE`，可通过`early_param("vsyscall", vsyscall_setup);`来设置。

当`vsyscall_mode`设置为`EMULATE`时，将`physaddr_vsyscall`映射到`fixmap`；设置为`XONLY`时，将`gate_vma.vm_flags`设置为`EXEC`(可执行)标记，`gate_vma`是一个`struct vm_area_struct`，即内存区域结构。

## 15 SMP设置

### 15.1 获取SMP配置

在前面，我们通过`find_smp_config`函数查找SMP配置信息，现在我们需要调用`get_smp_config`函数获取SMP的配置信息。`get_smp_config`函数调用`x86_init.mpparse.get_smp_config(0);`，指向`default_get_smp_config`。`default_get_smp_config`函数在[arch/x86/kernel/mpparse.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/mpparse.c#L503)中实现。

`default_get_smp_config`首先检查`smp_found_config`变量（`smp_scan_config`找到SMP配置的标记），`mpf_found`等变量；存在`smp`配置信息后，从内存中读取`struct mpf_intel`，进行相关初始化，如：`feature1`标记，检查`physptr`等。

### 15.2 CPU设置

接下来，调用`prefill_possible_map`函数，填充所有可用的CPU的`cpumask`，设置为在线状态。该函数[arch/x86/kernel/smpboot.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/smpboot.c#L1451)中实现。

`init_cpu_to_node`函数在初始化早期设置所有可用CPU到NUMA节点。该函数在[arch/x86/mm/numa.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/numa.c#L750)中实现。

## 16 `setup_arch`的其余部分

前面只是介绍了`setup_arch`函数中部分初始化功能，其他的功能当然很重要，但这些细节不会包含在这部分。剩余的部分包含了和`NUMA`、`SMP`、`APIC`、`APIC`、`EFI`相关特性。如：

* **`init_apic_mappings`**

`init_apic_mappings`函数设置本地[APIC](https://en.wikipedia.org/wiki/Advanced_Programmable_Interrupt_Controller)的地址。在[arch/x86/kernel/apic/apic.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/apic.c#L2084)中实现。

* **`io_apic_init_mappings`**

`io_apic_init_mappings`函数初始化本地 I/O APIC。在[arch/x86/kernel/apic/io_apic.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/io_apic.c#L2659)中实现。

* **`x86_init.resources.reserve_resources`**

`x86_init.resources.reserve_resources`函数指向的是`reserve_standard_io_resources`，保留标准I/O资源（如：`DMA`，`timer`、`FPU`等）。在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup.c#L635)中实现。

* **`mcheck_init`**

`mcheck_init`函数初始化[MCE, Machine check exception](https://en.wikipedia.org/wiki/Machine-check_exception)。在[arch/x86/kernel/cpu/mce/core.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/mce/core.c#L1978)中实现。

* **`register_refined_jiffies`**

`register_refined_jiffies`函数注册[Jiffy](https://en.wikipedia.org/wiki/Jiffy_(time))。在[kernel/time/jiffies.c](https://github.com/torvalds/linux/blob/v5.4/kernel/time/jiffies.c#L94)中实现。

* **`unwind_init`**

`unwind_init`函数初始化栈展开信息。在[arch/x86/kernel/unwind_orc.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/unwind_orc.c#L261)中实现。对在[include/asm-generic/vmlinux.lds.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/vmlinux.lds.h#L752)中定义`orc_unwind_ip`，`orc_unwind`，`orc_lookup`信息进行排序。

## 17 结束语

本文描述了Linux内核平台相关初始化过程，主要进行内存、CPU、内核早期参数设置、外接设备等初始化。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
