# Linux内核初始化 （第二部分）

## 0 内核入口点的最后准备

在上一篇的最后，Linux内核在`arch/x86/kernel/head_64.S`汇编代码中调用`x86_64_start_kernel`，现在我们进行内核入口点的最后准备。

## 1 平台入口点（`x86_64_start_kernel`）

`x86_64_start_kernel`函数在[arch/x86/kernel/head64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head64.c#L425)中实现，实现过程如下：

### 1.1 边界检查

首先，进行一些检查工作，针对内核镜像大小，模块区域映射边界检查等。如下：

```C
	BUILD_BUG_ON(MODULES_VADDR < __START_KERNEL_map);
	BUILD_BUG_ON(MODULES_VADDR - __START_KERNEL_map < KERNEL_IMAGE_SIZE);
	BUILD_BUG_ON(MODULES_LEN + KERNEL_IMAGE_SIZE > 2*PUD_SIZE);
	BUILD_BUG_ON((__START_KERNEL_map & ~PMD_MASK) != 0);
	BUILD_BUG_ON((MODULES_VADDR & ~PMD_MASK) != 0);
	BUILD_BUG_ON(!(MODULES_VADDR > __START_KERNEL));
	MAYBE_BUILD_BUG_ON(!(((MODULES_END - 1) & PGDIR_MASK) ==
				(__START_KERNEL & PGDIR_MASK)));
	BUILD_BUG_ON(__fix_to_virt(__end_of_fixed_addresses) <= MODULES_END);
```

`BUILD_BUG_ON`是一个宏定义，定义如下：

```C
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
```

`!!(condition)`等价于`condition != 0`，如果`condition`为真，则`!!(condition)`值为1，否则为0。`2*!!(condition)`的结果为`2`或`0`。因此，`BUILD_BUG_ON`执行完后可能产生两个不同的行为：

* `condition`为true，产生编译错误，我们尝试获取一个字符数组的`-1`索引；
* `condition`为false，编译正常。

### 1.2 初始化`cr4`影子

保存`cr4`的shadow copy，在禁用中断时CPU的`cr4`寄存器被保护，需要保存每个CPU中`cr4`内容。调用`cr4_init_shadow`函数实现，在[arch/x86/include/asm/tlbflush.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/tlbflush.h#L280)中定义。

### 1.3 重置页表信息

#### 1.3.1 重置早期页表

接下来，调用`reset_early_page_tables`重置所有的全局目录项(`early_top_pgt`)，并向`cr3`中写入全局页目录地址。

```C
	memset(early_top_pgt, 0, sizeof(pgd_t)*(PTRS_PER_PGD-1));
	next_early_pgt = 0;
	write_cr3(__sme_pa_nodebug(early_top_pgt));
```

`__sme_pa_nodebug`定义为`(__pa_nodebug(x) | sme_me_mask)`，`__pa_nodebug`定义为`__phys_addr_nodebug((unsigned long)(x))`。`__phys_addr_nodebug`定义为：

```C
static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;
	/* use the carry flag to determine if x was < __START_KERNEL_map */
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));
	return x;
}
```

#### 1.3.2 重置`bss`

调用`clear_bss`，重置`__bss_start`至`__bss_stop`区间。

#### 1.3.3 重置`init_top_pgt`

调用`clear_page`，重置`init_top_pgt`页表。

`init_top_pgt`在[arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head_64.S#L388)中定义。如下：

```C
#if defined(CONFIG_XEN_PV) || defined(CONFIG_PVH)
NEXT_PGD_PAGE(init_top_pgt)
	.quad   level3_ident_pgt - __START_KERNEL_map + _KERNPG_TABLE_NOENC
	.org    init_top_pgt + L4_PAGE_OFFSET*8, 0
	.quad   level3_ident_pgt - __START_KERNEL_map + _KERNPG_TABLE_NOENC
	.org    init_top_pgt + L4_START_KERNEL*8, 0
	/* (2^48-(2*1024*1024*1024))/(2^39) = 511 */
	.quad   level3_kernel_pgt - __START_KERNEL_map + _PAGE_TABLE_NOENC
	.fill	PTI_USER_PGD_FILL,8,0
    ...
#else
NEXT_PGD_PAGE(init_top_pgt)
	.fill	512,8,0
	.fill	PTI_USER_PGD_FILL,8,0
#endif
```

即，`init_top_pgt`为`512`个空的页表项。

`clear_page`在[arch/x86/include/asm/page_64.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page_64.h#L47)中定义，如下：

```C
static inline void clear_page(void *page)
{
	alternative_call_2(clear_page_orig,
			   clear_page_rep, X86_FEATURE_REP_GOOD,
			   clear_page_erms, X86_FEATURE_ERMS,
			   "=D" (page),
			   "0" (page)
			   : "cc", "memory", "rax", "rcx");
}
```

`clear_page_orig`在[arch/x86/lib/clear_page_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/lib/clear_page_64.S#L24)中定义，如下:

```C
ENTRY(clear_page_orig)
	xorl   %eax,%eax
	movl   $4096/64,%ecx
	.p2align 4
.Lloop:
	decl	%ecx
#define PUT(x) movq %rax,x*8(%rdi)
	movq %rax,(%rdi)
	PUT(1)
	PUT(2)
	PUT(3)
	PUT(4)
	PUT(5)
	PUT(6)
	PUT(7)
	leaq	64(%rdi),%rdi
	jnz	.Lloop
	nop
	ret
ENDPROC(clear_page_orig)
EXPORT_SYMBOL_GPL(clear_page_orig)
```

`clear_page_orig`将使用一个64次的循环，每次循环将`64`字节置零。

### 1.4 SME初期设置

`sme_early_init`在[arch/x86/mm/mem_encrypt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/mem_encrypt.c#L180)中定义。

在`SME`启用的情况下(`sme_me_mask`不为0)，通过或间接通过`__sme_set`修改`early_pmd_flags`, `__supported_pte_mask`, `protection_map`的地址。

`__sme_set`定义为`((x) | sme_me_mask)`。

### 1.5 KASAN初期设置

`kasan_early_init`在[arch/x86/mm/kasan_init_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/kasan_init_64.c#L265)中定义。

首先，计算`pte`, `pmd`, `pud`, `p4d`的值；移除不支持`__PAGE_KERNEL`掩码；初始化`kasan_early_shadow_pte`, `kasan_early_shadow_pmd`, `kasan_early_shadow_pud`, `kasan_early_shadow_p4d`。以`pmd`为例，如下：

```C
	pmdval_t pmd_val = __pa_nodebug(kasan_early_shadow_pte) | _KERNPG_TABLE;
	pmd_val &= __default_kernel_pte_mask;
	for (i = 0; i < PTRS_PER_PMD; i++)
		kasan_early_shadow_pmd[i] = __pmd(pmd_val);
```

在进行上述初始化后，调用`kasan_map_early_shadow`函数，初始化`early_top_pgt`, `init_top_pgt`。

`kasan_map_early_shadow`实现如下：

```C
static void __init kasan_map_early_shadow(pgd_t *pgd)
{
	/* See comment in kasan_init() */
	unsigned long addr = KASAN_SHADOW_START & PGDIR_MASK;
	unsigned long end = KASAN_SHADOW_END;
	unsigned long next;

	pgd += pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		kasan_early_p4d_populate(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}
```

`kasan_early_p4d_populate`按需分配`pgd`, `p4d`页表。

### 1.6 初期中断表设置

#### 1.6.1 中断介绍

[中断(interrupt)](https://en.wikipedia.org/wiki/Interrupt)是一个事件，该事件通过中断信号改变CPU执行的顺序。当中断信号到达时，CPU暂停当前执行的任务，并且切换到一个新的程序执行，这个程序叫做[中断处理程序(Interrupt handler)](https://en.wikipedia.org/wiki/Interrupt_handler)。中断处理程序对中断进行处理，在完成处理后将控制权交还给之前暂停的任务。

中断通常分为三类：

* 中断（异步中断）- 由硬件设备产生IRQ(Interrupt ReQuest)， 分为可屏蔽中断(maskable interrupt)和非屏蔽中断(nomaskable interrupt);
* 异常（同步中断）- CPU执行指令时探测到一个错误条件时产生的异常；
* 软中断 - 软件向CPU发送指令，触发编程异常。有两个常用的用途：系统调用和给调试程序发送特定事件；

每个中断好异常是由`0 ~ 255`之间的一个数标识，通常这个数叫做`向量(vector)`。在实践中前`32`个向量号用来表示异常，`32 ~ 255`用来表示用户定义的中断。

CPU从APIC或CPU引脚接收中断，使用中断向量号作为[中断描述表(Interrupt descriptor table，IDT)](https://en.wikipedia.org/wiki/Interrupt_descriptor_table)的索引。`0 ~ 31`号异常如下：

```text
----------------------------------------------------------------------------------------------
|Vector|Mnemonic|Description         |Type |Error Code|Source                                |
----------------------------------------------------------------------------------------------
|0     | #DE    |Division by zero    |Fault|NO        |DIV and IDIV                          |
|---------------------------------------------------------------------------------------------
|1     | #DB    |Debug               |F/T  |NO        |                                      |
|---------------------------------------------------------------------------------------------
|2     | ---    |NMI                 |INT  |NO        |external NMI                          |
|---------------------------------------------------------------------------------------------
|3     | #BP    |Breakpoint          |Trap |NO        |INT 3                                 |
|---------------------------------------------------------------------------------------------
|4     | #OF    |Overflow            |Trap |NO        |INTO  instruction                     |
|---------------------------------------------------------------------------------------------
|5     | #BR    |Bound Range Exceeded|Fault|NO        |BOUND instruction                     |
|---------------------------------------------------------------------------------------------
|6     | #UD    |Invalid Opcode      |Fault|NO        |UD2 instruction                       |
|---------------------------------------------------------------------------------------------
|7     | #NM    |Device Not Available|Fault|NO        |Floating point or [F]WAIT             |
|---------------------------------------------------------------------------------------------
|8     | #DF    |Double Fault        |Abort|YES       |An instruction which can generate NMI |
|---------------------------------------------------------------------------------------------
|9     | ---    |Reserved            |Fault|NO        |                                      |
|---------------------------------------------------------------------------------------------
|10    | #TS    |Invalid TSS         |Fault|YES       |Task switch or TSS access             |
|---------------------------------------------------------------------------------------------
|11    | #NP    |Segment Not Present |Fault|NO        |Accessing segment register            |
|---------------------------------------------------------------------------------------------
|12    | #SS    |Stack-Segment Fault |Fault|YES       |Stack operations                      |
|---------------------------------------------------------------------------------------------
|13    | #GP    |General Protection  |Fault|YES       |Memory reference                      |
|---------------------------------------------------------------------------------------------
|14    | #PF    |Page fault          |Fault|YES       |Memory reference                      |
|---------------------------------------------------------------------------------------------
|15    | ---    |Reserved            |     |NO        |                                      |
|---------------------------------------------------------------------------------------------
|16    | #MF    |x87 FPU fp error    |Fault|NO        |Floating point or [F]Wait             |
|---------------------------------------------------------------------------------------------
|17    | #AC    |Alignment Check     |Fault|YES       |Data reference                        |
|---------------------------------------------------------------------------------------------
|18    | #MC    |Machine Check       |Abort|NO        |                                      |
|---------------------------------------------------------------------------------------------
|19    | #XM    |SIMD fp exception   |Fault|NO        |SSE[2,3] instructions                 |
|---------------------------------------------------------------------------------------------
|20    | #VE    |Virtualization exc. |Fault|NO        |EPT violations                        |
|---------------------------------------------------------------------------------------------
|21-31 | ---    |Reserved            |INT  |NO        |External interrupts                   |
----------------------------------------------------------------------------------------------
```

中断描述表(Interrupt descriptor table，IDT)是一个系统表，与每一个中断或异常向量相联系，每一个向量在表中有相应的中断或异常处理程序的入口地址。内核在运行中断发生前，必须适当的初始化IDT。

和之前介绍的GDT和LDT类似，IDT表中的每个向量由8字节（32位模式下)或16字节（64位模式下）组成，我们通常把IDT中的每一项叫做`门(gate)`。CPU通过`idtr`寄存器存放这个IDT，它指定IDT的线性基地址及其限制长度。在运行中断前，必须用`lidt`指令初始化`lidtr`。

64模式下IDT每一项的结构如下：

```text
127                                                                            96
 --------------------------------------------------------------------------------
|                                                                               |
|                                Reserved                                       |
|                                                                               |
 --------------------------------------------------------------------------------
95                                                                             64
 --------------------------------------------------------------------------------
|                                                                               |
|                               Offset 63..32                                   |
|                                                                               |
 --------------------------------------------------------------------------------
63                                   48  47 46 45 44     40 39       35 34     32
 --------------------------------------------------------------------------------
|                                      |   |  D  |         |           |        |
|       Offset 31..16                  | P |  P  |   Type  |    zero   |  IST   |
|                                      |   |  L  |         |           |        |
 --------------------------------------------------------------------------------
31                                   16 15                                      0
 --------------------------------------------------------------------------------
|                                      |                                        |
|          Segment Selector            |                 Offset 15..0           |
|                                      |                                        |
 --------------------------------------------------------------------------------
```

字段说明如下：

* offset - 到中断处理程序入口点的偏移；
* DPL - 描述符特权级别；
* P - Segment Present 标志;
* Segment selector - 在GDT或LDT中的代码段选择符；
* IST - 用来为中断处理提供一个新的栈；
* Type - 描述符的类型，分别为：`0x5`:任务描述符；`0xE`:中断描述符；`0xF`:陷阱描述符。

**任务门(task gate)**
当中断信号发生时，必须取代当前进程的那个进程的TSS选择符存放在任务门中。

**中断门(interrupt gate)**
包含段选择符和中断或异常处理程序的段内偏移量。当控制权转移到中断处理程序时，CPU清除`IF`标记，从而关闭将来会发生的可屏蔽中断。在当前中断处理程序返回时，CPU通过`iret`指令重新设置`IF`标记位。

**陷阱门(trap gate)**
处理过程与中断门相似，在将控制权转移到中断处理程序时不修改`IF`标记。

CPU处理中断的过程如下：

* 检查当前特权等级（CPL）和描述符特权等级（DPL）;
* CPU在栈上保存`eflags`(标记寄存器),`cs`(代码段寄存器),`ip`(程序计数器)；
* 如果异常产生了一个硬件出错码，CPU将它保存在栈上；
* 装载`cs`,`ip`寄存器，其值分别为IDT表中门描述中的`段选择符`和`偏移量`字段；跳转到中断或异常处理程序；
* 中断或异常处理程序处理完成后，通过`lret`指令返回，将控制权交给被中断的进程。

#### 1.6.2 Linux设置IDT的过程

Linux内核使用`gate_desc`来表示IDT，在[arch/x86/include/asm/desc_defs.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/desc_defs.h#L77)定义。如下：

```C
struct idt_bits {
	u16		ist	: 3,
			zero	: 5,
			type	: 5,
			dpl	: 2,
			p	: 1;
} __attribute__((packed));

struct gate_struct {
	u16		offset_low;
	u16		segment;
	struct idt_bits	bits;
	u16		offset_middle;
#ifdef CONFIG_X86_64
	u32		offset_high;
	u32		reserved;
#endif
} __attribute__((packed));

typedef struct gate_struct gate_desc;
```

`idt_setup_early_handler`在[arch/x86/kernel/idt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/idt.c#L331)中定义。如下：

```C
	for (i = 0; i < NUM_EXCEPTION_VECTORS; i++)
		set_intr_gate(i, early_idt_handler_array[i]);
#ifdef CONFIG_X86_32
	for ( ; i < NR_VECTORS; i++)
		set_intr_gate(i, early_ignore_irq);
#endif
	load_idt(&idt_descr);
```

可以看到，循环调用`set_intr_gate`后，调用`load_idt`设置`idt`。

* **early_idt_handler_array**定义
  
首先，我们看下`early_idt_handler_array`的定义，它在[arch/x86/include/asm/segment.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/segment.h#L289)中定义，如下：

```C
#define IDT_ENTRIES			256
#define NUM_EXCEPTION_VECTORS		32

#define EARLY_IDT_HANDLER_SIZE 9

extern const char early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE];
```

可以看到`early_idt_handler_array`是一个32项的数组，每一项`9`字节。其中`2`个字节备用，用于向栈中压入错误码（没有错误码时，压入0）；2个字节用于向栈中压入向量号；`5`个字节用于异常处理程序地址。

* **set_intr_gate**

`set_intr_gate`在同一个文件中定义，如下：

```C
	struct idt_data data;

	BUG_ON(n > 0xFF);

	memset(&data, 0, sizeof(data));
	data.vector	= n;
	data.addr	= addr;
	data.segment	= __KERNEL_CS;
	data.bits.type	= GATE_INTERRUPT;
	data.bits.p	= 1;

	idt_setup_from_table(idt_table, &data, 1, false);
```

使用`idt_data`结构来进行中间转换，进行必要检查后，填充相关字段后，调用`idt_setup_from_table`。`idt_table`是所有的IDT信息，如下：

```C
gate_desc idt_table[IDT_ENTRIES] __page_aligned_bss;
```

* **idt_setup_from_table**

`idt_setup_from_table`也在同一个文件中定义，如下：

```C
static void
idt_setup_from_table(gate_desc *idt, const struct idt_data *t, int size, bool sys)
{
	gate_desc desc;

	for (; size > 0; t++, size--) {
		idt_init_desc(&desc, t);
		write_idt_entry(idt, t->vector, &desc);
		if (sys)
			set_bit(t->vector, system_vectors);
	}
}
```

首先，将`idt_data`转换为`gate_desc`；然后，调用`write_idt_entry`写入`idt`中对应向量中；最后，如果是系统向量，修改`system_vectors`对应bit项。

* **load_idt**
  
`load_idt`加载`idt_descr`到`ldtr`寄存器中。`idt_descr`定义如下：

```C
struct desc_ptr idt_descr __ro_after_init = {
	.size		= (IDT_ENTRIES * 2 * sizeof(unsigned long)) - 1,
	.address	= (unsigned long) idt_table,
};
```

#### 1.6.3 初期中断处理程序

* **early_idt_handler_array的定义**

在上一部分，我们将`early_idt_handler_array`填充到IDT中，这部分我们对其一探究竟。在[arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head_64.S#L276)中我们找到其定义，如下：

```C
ENTRY(early_idt_handler_array)
	i = 0
	.rept NUM_EXCEPTION_VECTORS
	.if ((EXCEPTION_ERRCODE_MASK >> i) & 1) == 0
		UNWIND_HINT_IRET_REGS
		pushq $0	# Dummy error code, to make stack frame uniform
	.else
		UNWIND_HINT_IRET_REGS offset=8
	.endif
	pushq $i		# 72(%rsp) Vector number
	jmp early_idt_handler_common
	UNWIND_HINT_IRET_REGS
	i = i + 1
	.fill early_idt_handler_array + i*EARLY_IDT_HANDLER_SIZE - ., 1, 0xcc
	.endr
	UNWIND_HINT_IRET_REGS offset=16
END(early_idt_handler_array)
```

可以看到，每个项都类似如下代码：

```C
6a 00                   pushq  $0x0
6a 00                   pushq  $0x0
e9 17 01 00 00          jmpq   <early_idt_handler_common>
```

* **early_idt_handler_common的实现**

接下来，我们来看`early_idt_handler_common`的实现，如下：

```C
early_idt_handler_common:
	/*
	 * The stack is the hardware frame, an error code or zero, and the
	 * vector number.
	 */
	cld

	incl early_recursion_flag(%rip)

	/* The vector number is currently in the pt_regs->di slot. */
	pushq %rsi				/* pt_regs->si */
	movq 8(%rsp), %rsi			/* RSI = vector number */
	movq %rdi, 8(%rsp)			/* pt_regs->di = RDI */
	pushq %rdx				/* pt_regs->dx */
	pushq %rcx				/* pt_regs->cx */
	pushq %rax				/* pt_regs->ax */
	pushq %r8				/* pt_regs->r8 */
	pushq %r9				/* pt_regs->r9 */
	pushq %r10				/* pt_regs->r10 */
	pushq %r11				/* pt_regs->r11 */
	pushq %rbx				/* pt_regs->bx */
	pushq %rbp				/* pt_regs->bp */
	pushq %r12				/* pt_regs->r12 */
	pushq %r13				/* pt_regs->r13 */
	pushq %r14				/* pt_regs->r14 */
	pushq %r15				/* pt_regs->r15 */
	UNWIND_HINT_REGS

	cmpq $14,%rsi		/* Page fault? */
	jnz 10f
	GET_CR2_INTO(%rdi)	/* can clobber %rax if pv */
	call early_make_pgtable
	andl %eax,%eax
	jz 20f			/* All good */

10:
	movq %rsp,%rdi		/* RDI = pt_regs; RSI is already trapnr */
	call early_fixup_exception

20:
	decl early_recursion_flag(%rip)
	jmp restore_regs_and_return_to_kernel
END(early_idt_handler_common)
```

执行过程如下：

1. 增加`early_recursion_flag`的值，预防递归调用；`early_recursion_flag`定义如下：

    ```C
        .balign 4
    GLOBAL(early_recursion_flag)
        .long 0
    ```

2. 保存通用寄存器的值；
   首先，获取中断向量，保存到`rsi`寄存器中；然后保存通用集群器到栈上；

3. 根据向量值，执行不同的中断处理程序；
   如果是`14`，即`#PF`或[页错误（Page Fault）](https://en.wikipedia.org/wiki/Page_fault)，调用`early_make_pgtable`函数；
   如果是其他值，调用`early_fixup_exception`.

4. 减少`early_recursion_flag`值；
5. 调用`restore_regs_and_return_to_kernel`恢复到之前的处理状态；

#### 1.6.4 页错误（#PF）中断处理程序

在上一节中，我们检查中断向量值是缺页的情况下调用`early_make_pgtable`来创建新的页表。这里我们提供`#PF`中断处理程序，便于之后将内核加载到`4G`地址以上，并且能够访问位于4G以上的`boot_params`结构。

* **early_make_pgtable**

`early_make_pgtable`在[arch/x86/kernel/head64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head64.c#L370)中定义，它有一个参数，`cr2`寄存器里的值，即引起缺页的地址。代码如下：

```C
int __init early_make_pgtable(unsigned long address)
{
	unsigned long physaddr = address - __PAGE_OFFSET;
	pmdval_t pmd;

	pmd = (physaddr & PMD_MASK) + early_pmd_flags;

	return __early_make_pgtable(address, pmd);
}
```

`__PAGE_OFFSET`在[arch/x86/include/asm/page_64_types.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page_64_types.h#L44)中定义，表示`__PAGE_OFFSET_BASE_L4`或`__PAGE_OFFSET_BASE_L5`（5级页表启用的情况下）.

```C
#define __PAGE_OFFSET_BASE_L5	_AC(0xff11000000000000, UL)
#define __PAGE_OFFSET_BASE_L4	_AC(0xffff888000000000, UL)

#ifdef CONFIG_DYNAMIC_MEMORY_LAYOUT
#define __PAGE_OFFSET           page_offset_base
#else
#define __PAGE_OFFSET           __PAGE_OFFSET_BASE_L4
#endif /* CONFIG_DYNAMIC_MEMORY_LAYOUT */
```

`_AC`是个宏定义，如下：

```C
#ifdef __ASSEMBLY__
#define _AC(X,Y)	X
#define _AT(T,X)	X
#else
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#endif
```

即，`__PAGE_OFFSET`展开为`0xffff888000000000`或`0xff11000000000000`。但是，为什么虚拟地址减去`__PAGE_OFFSET`就是物理地址? 我们在[Documentation/x86/x86_64/mm.rst](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/x86_64/mm.rst)找到相关答案。

```text
#Complete virtual memory map with 4-level page tables
ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping of all physical memory (page_offset_base)

#Complete virtual memory map with 5-level page tables
ff11000000000000 |  -59.75 PB | ff90ffffffffffff |   32 PB | direct mapping of all physical memory (page_offset_base)
```

以4级页表为例，`0xffff888000000000 ~ 0xffffc87fffffffff`这个区间直接映射了所有的物理内存。当内核访问所有的物理内存时，使用直接映射即可。

* **__early_make_pgtable**

`early_make_pgtable`在初始化`pmd`后，和`address`一起传入`__early_make_pgtable`。`__early_make_pgtable`在同一个文件中定义，如下：

```C
/* Create a new PMD entry */
int __init __early_make_pgtable(unsigned long address, pmdval_t pmd)
{
	unsigned long physaddr = address - __PAGE_OFFSET;
	pgdval_t pgd, *pgd_p;
	p4dval_t p4d, *p4d_p;
	pudval_t pud, *pud_p;
	pmdval_t *pmd_p;
    ...
}
```

1. 改函数从定义`*val_t`类型的变量开始，这些所有的类型都使用`typedef`被声明为`unsigned long`的别名；

2. 在检查物理地址有效后，在`early_top_pgt`获取pgd条目的地址；如下：

   ```C
   again:
	pgd_p = &early_top_pgt[pgd_index(address)].pgd;
	pgd = *pgd_p;
   ```

3. 检查是否支持5级页表，不支持5级页表的情况下，获取`p4d_p = pgd_p`；

4. 在支持5级页表的情况下，检查`pgd`是否存在。存在的话，将`pgd`的基地址分配给`p4d_p`，如下：

   ```C
		p4d_p = (p4dval_t *)((pgd & PTE_PFN_MASK) + __START_KERNEL_map - phys_base);
   ```

   `PTE_PFN_MASK`是一个宏定义，是`(pte|pmd|pud|pgd)val_t`中`4KB`大小页掩码。

5. 在`pgd`不存在的情况下，从不超过`EARLY_DYNAMIC_PAGE_TABLES`（即，64）个页表中按需设置页表; 如果超过了`EARLY_DYNAMIC_PAGE_TABLES`，我们重置页表，并从跳转到`again`重新开始。如下：

    ```C
		if (next_early_pgt >= EARLY_DYNAMIC_PAGE_TABLES) {
			reset_early_page_tables();
			goto again;
		}

		p4d_p = (p4dval_t *)early_dynamic_pgts[next_early_pgt++];
		memset(p4d_p, 0, sizeof(*p4d_p) * PTRS_PER_P4D);
		*pgd_p = (pgdval_t)p4d_p - __START_KERNEL_map + phys_base + _KERNPG_TABLE;
    ```

6. 将`p4d_p`指向正确的页表项，并将其值赋值给`p4d`;

7. 重复步骤4-6；获取`pud_p`和`pmd_p`;

8. 最后，将`pmd`赋值给`pmd_p`的某个条目：

   ```C
	pmd_p[pmd_index(address)] = pmd;
   ```

经过上述步骤后，`early_top_pgt`中包含有效地址的条目。

#### 1.6.5 其他异常中断处理程序

在初期中断阶段，除页错误之外的其他异常，由`early_fixup_exception`处理，它接受两个参数 - 指向内核堆栈的指针和中断向量。

`early_fixup_exception`在[arch/x86/mm/extable.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/extable.c#L233)中定义。如下：

```C
/* Restricted version used during very early boot */
void __init early_fixup_exception(struct pt_regs *regs, int trapnr)
{
    ...
    ...
    ...
}
```

* **必要的检查**

首先，我们进行一些检查，包括：忽略NMI；确保我们没有处于递归情况；运行在正确的代码段下。

* **fixup_exception**

之后，我们调用`fixup_exception`函数找到实际的中断处理程序并调用它。如下：

```C
int fixup_exception(struct pt_regs *regs, int trapnr, unsigned long error_code,
		    unsigned long fault_addr)
{
	const struct exception_table_entry *e;
	ex_handler_t handler;

#ifdef CONFIG_PNPBIOS
...
#endif

	e = search_exception_tables(regs->ip);
	if (!e)
		return 0;

	handler = ex_fixup_handler(e);
	return handler(e, regs, trapnr, error_code, fault_addr);
}
```

`ex_handler_t`是一个函数指针，定义如下：

```C
typedef bool (*ex_handler_t)(const struct exception_table_entry *,
			    struct pt_regs *, int, unsigned long,
			    unsigned long);
```

`search_exception_tables`函数在[kernel/extable.c](https://github.com/torvalds/linux/blob/v5.4/kernel/extable.c#L52)中定义，其功能是从异常表中查找给定的地址，(即，ELF文件中`__ex_table`部分)。

之后，通过`ex_fixup_handler`获取实际地址，最后，我们调用实际的处理程序。

关于异常表的更多信息，可以参考[Documentation/x86/exception-tables.rst](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/exception-tables.rst)。

* **fixup_bug**

`search_exception_tables`函数在[arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/traps.c#L174)中定义。如下：

```C
int fixup_bug(struct pt_regs *regs, int trapnr)
{
	if (trapnr != X86_TRAP_UD)
		return 0;

	switch (report_bug(regs->ip, regs)) {
	case BUG_TRAP_TYPE_NONE:
	case BUG_TRAP_TYPE_BUG:
		break;

	case BUG_TRAP_TYPE_WARN:
		regs->ip += LEN_UD2;
		return 1;
	}

	return 0;
}
```

该函数在中断向量是`#UD`(或者，无效操作符(`Invalid Opcode`))的情况下，并且`report_bug`为`BUG_TRAP_TYPE_WARN`的情况下返回1，其他情况下返回0。

### 1.7 复制启动信息

接下来，我们调用`copy_bootdata(__va(real_mode_data));`函数，复制`boot_params`和`boot_command_line`。`copy_bootdata`在`arch/x86/kernel/head64.c`文件中定义。

首先，我们来看下`__va`的定义，`__va`在[arch/x86/include/asm/page.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page.h#L59)中定义，如下：

```C
#ifndef __va
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))
#endif
```

`PAGE_OFFSET`在上节提到，即`__PAGE_OFFSET`，是虚拟地址与物理地址之间映射的偏移量。

`boot_params`在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup.c#L141)中定义，`boot_command_line`在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L134)定义。

`copy_bootdata`在复制`boot_params`时，调用`sanitize_boot_params(&boot_params);`函数，填充引导阶段未能正常初始化`boot_params`中的一些字段，比如：`ext_ramdisk_image`等。

`get_cmd_line_ptr`函数获取命令行的64位地址，如下：

```C
static unsigned long get_cmd_line_ptr(void)
{
	unsigned long cmd_line_ptr = boot_params.hdr.cmd_line_ptr;
	cmd_line_ptr |= (u64)boot_params.ext_cmd_line_ptr << 32;
	return cmd_line_ptr;
}
```

### 1.8 加载早期微代码

[Microcode](https://en.wikipedia.org/wiki/Microcode)是CPU和指令集之间的一层组件技术，用于调整和更改CPU电路状态。这里调用`load_ucode_bsp`函数加载。

### 1.9 内核地址映射

在前面`reset_early_page_tables`函数中，我们清除了大部分的页表项，只保留了内核高地址映射。并且通过`clear_page(init_top_pgt)`函数将`init_top_pgt`全部清零。现在将`init_top_pgt`最后一项设置为内核高地址映射。

```C
init_top_pgt[511] = early_top_pgt[511];
```

### 1.10 调用`x86_64_start_reservations`

经过上面的初始化后，调用`x86_64_start_reservations`进行后续初始化。

## 2 平台相关设置（`x86_64_start_reservations`）

`x86_64_start_reservations`同样在`arch/x86/kernel/head64.c`中定义，如下:

```C
void __init x86_64_start_reservations(char *real_mode_data)
{
	/* version is always not zero if it is copied */
	if (!boot_params.hdr.version)
		copy_bootdata(__va(real_mode_data));

	x86_early_init_platform_quirks();

	switch (boot_params.hdr.hardware_subarch) {
	case X86_SUBARCH_INTEL_MID:
		x86_intel_mid_early_setup();
		break;
	default:
		break;
	}

	start_kernel();
}
```

### 2.1 检查并复制启动信息

首先，检查`boot_params.hdr.version`信息，如果不存在，再次调用`copy_bootdata`。

### 2.2 `x86`平台早期初始化

接下来，调用`x86_early_init_platform_quirks`，在[arch/x86/kernel/platform-quirks.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/platform-quirks.c#L8)中定义，实现如下：

```C
void __init x86_early_init_platform_quirks(void)
{
	x86_platform.legacy.i8042 = X86_LEGACY_I8042_EXPECTED_PRESENT;
	x86_platform.legacy.rtc = 1;
	x86_platform.legacy.warm_reset = 1;
	x86_platform.legacy.reserve_bios_regions = 0;
	x86_platform.legacy.devices.pnpbios = 1;

	switch (boot_params.hdr.hardware_subarch) {
	case X86_SUBARCH_PC:
		x86_platform.legacy.reserve_bios_regions = 1;
		break;
	case X86_SUBARCH_XEN:
		x86_platform.legacy.devices.pnpbios = 0;
		x86_platform.legacy.rtc = 0;
		break;
	case X86_SUBARCH_INTEL_MID:
	case X86_SUBARCH_CE4100:
		x86_platform.legacy.devices.pnpbios = 0;
		x86_platform.legacy.rtc = 0;
		x86_platform.legacy.i8042 = X86_LEGACY_I8042_PLATFORM_ABSENT;
		break;
	}

	if (x86_platform.set_legacy_features)
		x86_platform.set_legacy_features();
}
```

可以看到，改函数是对`x86_platform`字段进行初始化。`x86_platform`在[arch/x86/include/asm/x86_init.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/x86_init.h#L299)声明，

```C
struct x86_platform_ops {
	unsigned long (*calibrate_cpu)(void);
	unsigned long (*calibrate_tsc)(void);
	void (*get_wallclock)(struct timespec64 *ts);
	int (*set_wallclock)(const struct timespec64 *ts);
	void (*iommu_shutdown)(void);
	bool (*is_untracked_pat_range)(u64 start, u64 end);
	void (*nmi_init)(void);
	unsigned char (*get_nmi_reason)(void);
	void (*save_sched_clock_state)(void);
	void (*restore_sched_clock_state)(void);
	void (*apic_post_init)(void);
	struct x86_legacy_features legacy;
	void (*set_legacy_features)(void);
	struct x86_hyper_runtime hyper;
};

...

extern struct x86_platform_ops x86_platform;
```

可以看到，`struct x86_platform_ops`是一个结构体，封装了`x86`架构CPU的属性信息和一些操作的回调函数。`x86_early_init_platform_quirks`根据不同系列CPU（如：PC，XEN，MID）设置`x86_platform.legacy`信息。`x86_platform`中的回调函数在[arch/x86/kernel/x86_init.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/x86_init.c#L111)中进行了初始化，如下：

```C
struct x86_platform_ops x86_platform __ro_after_init = {
	.calibrate_cpu			= native_calibrate_cpu_early,
	.calibrate_tsc			= native_calibrate_tsc,
	.get_wallclock			= mach_get_cmos_time,
	.set_wallclock			= mach_set_rtc_mmss,
	.iommu_shutdown			= iommu_shutdown_noop,
	.is_untracked_pat_range		= is_ISA_range,
	.nmi_init			= default_nmi_init,
	.get_nmi_reason			= default_get_nmi_reason,
	.save_sched_clock_state 	= tsc_save_sched_clock_state,
	.restore_sched_clock_state 	= tsc_restore_sched_clock_state,
	.hyper.pin_vcpu			= x86_op_int_noop,
};
```

### 2.3 `x86_intel`移动平台早期初始化

接下来，判断CPU是移动平台（即，`X86_SUBARCH_INTEL_MID`），调用`x86_intel_mid_early_setup`函数进行初始化。

`x86_intel_mid_early_setup`在[arch/x86/platform/intel-mid/intel-mid.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/platform/intel-mid/intel-mid.c#L155)中定义。实现过程同`x86_early_init_platform_quirks`类似，对`x86_init`, `x86_cpuinit`, `x86_platform`, `legacy_pic`, `pm_power_off`, `machine_ops`进行了修改或设置。

`x86_init`, `x86_cpuinit`, `x86_platform`在[arch/x86/include/asm/x86_init.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/x86_init.h#L297)进行声明，在[arch/x86/kernel/x86_init.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/x86_init.c#L39)进行了默认初始化。

`legacy_pic`, `default_legacy_pic`, `null_legacy_pic`在[arch/x86/include/asm/i8259.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/i8259.h#L57)进行定义，在[arch/x86/kernel/i8259.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/i8259.c#L397)进行了默认初始化。

`pm_power_off`在[include/linux/pm.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/pm.h#L22)进行声明，在[arch/x86/kernel/reboot.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/reboot.c#L40)中定义。

`machine_ops`在[arch/x86/include/asm/reboot.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/reboot.h#L18)进行声明，在[arch/x86/kernel/reboot.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/reboot.c#L751)进行了默认初始化。

### 2.4 `start_kernel`

在经过上述的早期初始后，我们终于完成了进入内核入口点的所有准备工作，现在进行早期初始化的最后一步，调用`start_kernel`进入内核入口点。

```C
	start_kernel();
```

## 3 结束语

本文描述了Linux内核平台入口点前的初始化，主要进行中断处理函数设置和平台相关设置。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
