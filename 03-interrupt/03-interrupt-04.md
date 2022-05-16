# 中断和中断处理 （第四部分）

## 0 非早期中断门的初始化

在上一部分中，我们详细描述了Linux内核早期异常（`#DB`和`#BP`）的中断处理过程。现在，我们停留在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup.c#L895)文件中`setup_arch`函数中调用的`idt_setup_early_traps`函数。在本文中，我们继续深入Linux内核中`x86_64`平台的中断和异常处理。接下来第一个关于中断和异常处理的是`idt_setup_early_pf`函数设置的`#PF`(page fault)中断处理。

## 1 `#PF`中断处理过程

### 1.1 设置`#PF`中断处理程序

`idt_setup_early_pf`函数在[arch/x86/kernel/idt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/idt.c#L279)中实现，如下：

```C
void __init idt_setup_early_pf(void)
{
	idt_setup_from_table(idt_table, early_pf_idts,
			     ARRAY_SIZE(early_pf_idts), true);
}
```

同`idt_setup_early_traps`函数类似，调用`idt_setup_from_table`函数来设置中断处理函数。`early_pf_idts`的定义如下：

```C
static const __initconst struct idt_data early_pf_idts[] = {
	INTG(X86_TRAP_PF,		page_fault),
};
```

即，通过`INTG`宏设置了`#PF`的中断向量`X86_TRAP_PF`及其中断处理函数`page_fault`。`page_fault`函数同样在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L1202)中定义，如下：

```C
idtentry page_fault		do_page_fault		has_error_code=1	read_cr2=1
```

同`#DB`和`#BP`中断处理函数一样，`#PF`同样使用`idtentry`宏进行中断处理，具体的处理过程参见上一篇文章。

### 1.2 `#PF`中断处理函数

`page_fault`的中断处理函数为`do_page_fault`，在[arch/x86/mm/fault.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/mm/fault.c#L1524)中实现。如下：

```C
dotraplinkage void
do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	enum ctx_state prev_state;

	prev_state = exception_enter();
	trace_page_fault_entries(regs, error_code, address);
	__do_page_fault(regs, error_code, address);
	exception_exit(prev_state);
}
```

`do_page_fault`函数使用三个参数，`regs`为`pt_regs`结构，保存中断处理程序的状态；`error_code`为异常的错误代码；`address`为触发异常的内存地址，通过读取`cr2`寄存器获取。

### 1.3 中断追踪

首先，调用`exception_enter`函数，`exception_enter`函数和`exception_exit`函数都在[include/linux/context_tracking.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/context_tracking.h#L48)中实现。这两个函数是Linux内核上下文追踪子系统函数，RCU使用它们来移除进程在用户空间的时间依赖。几乎所有的异常处理函数都有类似的代码：

```C
enum ctx_state prev_state;
prev_state = exception_enter();
...
... // exception handler here
...
exception_exit(prev_state);
```

`exception_enter`函数通过调用`context_tracking_is_enabled`函数检查`context tracking`是否启用。在启用状态时，通过`this_cpu_read`获取当前的上下文状态，如果不处于内核空间时，调用`context_tracking_exit`函数通知上下文追踪子系统当前处理器退出用户空间并进入内核空间。如下：

```C
static inline enum ctx_state exception_enter(void)
{
	enum ctx_state prev_ctx;
	if (!context_tracking_is_enabled())
		return 0;

	prev_ctx = this_cpu_read(context_tracking.state);
	if (prev_ctx != CONTEXT_KERNEL)
		context_tracking_exit(prev_ctx);
	return prev_ctx;
}
```

`ctx_state`包括下面几种状态：

```C
	enum ctx_state {
		CONTEXT_DISABLED = -1,	/* returned by ct_state() if unknown */
		CONTEXT_KERNEL = 0,
		CONTEXT_USER,
		CONTEXT_GUEST,
	} state;
```

### 1.4 `#PF`中断实现过程

在中断执行完成后，我们调用`exception_eixt`返回之前的上下文。在`exception_enter`和`exception_exit`之间，我们调用实际的页错误中断处理函数。如下：

```C
    trace_page_fault_entries(regs, error_code, address);
    __do_page_fault(regs, error_code, address);
```

`trace_page_fault_entries`函数在同一个文件中实现，在开启页错误追踪的情况下，根据`regs`寄存器的状态来进行用户空间(`trace_page_fault_user`)或内核空间(`trace_page_fault_kernel`)页错误追踪。

`__do_page_fault`函数也在同一个文件中实现，实现如下：

```C
static noinline void
__do_page_fault(struct pt_regs *regs, unsigned long hw_error_code,
		unsigned long address)
{
	prefetchw(&current->mm->mmap_sem);

	if (unlikely(kmmio_fault(regs, address)))
		return;

	/* Was the fault on kernel-controlled part of the address space? */
	if (unlikely(fault_in_kernel_space(address)))
		do_kern_addr_fault(regs, hw_error_code, address);
	else
		do_user_addr_fault(regs, hw_error_code, address);
}
```

`prefetchw`函数执行`prefetchw`指令，通过`X86_FEATURE_3DNOWPREFETCH`来预先获取外部的[缓存线(cache line)](https://en.wikipedia.org/wiki/CPU_cache)。预先获取的主要目的是为了减少内存访问的延时。

`kmmio_fault`函数也在同一个文件中实现，用来处理处于`kmmio`临界区页错误的情况，在`kmmio_handler`函数中实现其处理过程。

`fault_in_kernel_space`函数用来判断页错误的地址是否处于内核空间，如下：

```C
static int fault_in_kernel_space(unsigned long address)
{
	if (IS_ENABLED(CONFIG_X86_64) && is_vsyscall_vaddr(address))
		return false;

	return address >= TASK_SIZE_MAX;
}

...
#define TASK_SIZE_MAX	((1UL << __VIRTUAL_MASK_SHIFT) - PAGE_SIZE)
...
#ifdef CONFIG_X86_5LEVEL
#define __VIRTUAL_MASK_SHIFT	(pgtable_l5_enabled() ? 56 : 47)
#else
#define __VIRTUAL_MASK_SHIFT	47
#endif
```

`TASK_SIZE_MAX`宏展开后为`0x00007ffffffff000`(4级页表)或`0x00FFFFFFFFFFF000`(5级页表)。

此外，我们还注意到`unlikely`宏，在Linux内核中有两个类似的宏定义，如下：

```C
# define likely(x)	__builtin_expect(!!(x), 1)
# define unlikely(x)	__builtin_expect(!!(x), 0)
```

这两个宏定义在Linux内核中经常出现，主要目的是为了性能优化。在需要检查代码的判断条件时，我们已经知道很少会存在`true`或`false`的情况，通过这两个宏来告诉编译器。如果判断条件使用`unlikely`宏，编译器在分支预测时预设为`false`。

现在，让我们回到地址检查函数，根据页地址和`TASK_SIZE_MAX`来判断`#PF`发生在内核空间或用户空间。在内核空间下调用`do_kern_addr_fault`函数，在用户空间下调用`do_user_addr_fault`函数。有多种可能性会导致页错误，包括：内存未分配（vmalloc_fault）, TLB无效导致的可疑错误（spurious fault），内核探针错误（kprobes fault）等。

## 2 其他中断函数设置

在`setup_arch`函数中调用`early_trap_pf_init`函数设置`#PF`中断处理后，没有其他的中断或异常处理相关内容。在返回到[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L626)中的`start_kernel`函数后，第一个关于中断的函数是`trap_init`函数。`trap_init`函数在[arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/traps.c#L925)中实现，初始化剩余的异常处理函数（除`#DB`（调试，debug）、`#BP`（断点，breakpoint）、`#PF`（页错误，page fault）外的剩余异常）。

### 2.1 陷阱门设置（`idt_setup_traps`）

`trap_init`函数在调用`setup_cpu_entry_areas`函数初始化CPU后，调用`idt_setup_traps`函数来设置中断。`idt_setup_traps`函数同其他中断设置函数一样，通过`def_idts`中断表来设置中断。`def_idts`定义如下：

```C
static const __initconst struct idt_data def_idts[] = {
	INTG(X86_TRAP_DE,		divide_error),
	INTG(X86_TRAP_NMI,		nmi),
	INTG(X86_TRAP_BR,		bounds),
	INTG(X86_TRAP_UD,		invalid_op),
	INTG(X86_TRAP_NM,		device_not_available),
	INTG(X86_TRAP_OLD_MF,		coprocessor_segment_overrun),
	INTG(X86_TRAP_TS,		invalid_TSS),
	INTG(X86_TRAP_NP,		segment_not_present),
	INTG(X86_TRAP_SS,		stack_segment),
	INTG(X86_TRAP_GP,		general_protection),
	INTG(X86_TRAP_SPURIOUS,		spurious_interrupt_bug),
	INTG(X86_TRAP_MF,		coprocessor_error),
	INTG(X86_TRAP_AC,		alignment_check),
	INTG(X86_TRAP_XF,		simd_coprocessor_error),

#ifdef CONFIG_X86_32
	TSKG(X86_TRAP_DF,		GDT_ENTRY_DOUBLEFAULT_TSS),
#else
	INTG(X86_TRAP_DF,		double_fault),
#endif
	INTG(X86_TRAP_DB,		debug),

#ifdef CONFIG_X86_MCE
	INTG(X86_TRAP_MC,		&machine_check),
#endif

	SYSG(X86_TRAP_OF,		overflow),
#if defined(CONFIG_IA32_EMULATION)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_compat),
#elif defined(CONFIG_X86_32)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_32),
#endif
};
```

其中：

* `#DE` - divide error，除零错误；
* `#NMI` - Non-maskable Interrupt，不可屏蔽中断；
* `#BR` - Bound Range exceed，在`BOUND`指令执行时，超出边界时触发；
* `#UD` - Invalid Opcode，无效指令。在处理器尝试执行无效的或保留的指令码，或者执行无效的运行单元时触发；
* `#NM` - Device Not Available，设备不可用。在处理器`%cr0`寄存器中`EM`标记设置时执行`x87 FPU`浮点指令时触发；
* `#CSO` - Coprocessor Segment Overrun。该异常表示老式数学处理器[Coprocessor](https://en.wikipedia.org/wiki/Coprocessor)检测到页或段访问错误。现在的处理器不会触发该异常。
* `#TS` - Invalid TSS。指示在[任务状态段，TSS](https://en.wikipedia.org/wiki/Task_state_segment)中出现错误；
* `#NP` - Segment Not Present，段不存在。在段或门描述符中存在标记（present flag）清除时，在此期间加载`cs`, `ds`, `es`, `fs`, `gs`寄存器。
* `#SS` - Stack Fault，栈相关错误。检测到与栈相关错误，如：在访问`ss`寄存器时检测到不存在的栈段；
* `#GP` - General Protection，一般保护。在处理器检测到一种保护违规。存在多种情况会导致一般保护违规，如：在系统段选择器中加载`ss`, `ds`, `es`, `fs`, `gs`寄存器；在代码段或只读段进行写入；在IDT中的条目不是中断门、陷阱门或任务门；
* `#SPURIOUS` - spurious interrupt，不预期的硬件中断；
* `#MF` - x87 FPU Floating-Point Error，[x87 FPU](https://en.wikipedia.org/wiki/X86_instruction_listings#x87_floating-point_instructions)检测到浮点错误；
* `#AC` - Alignment Check，在对齐检查开启的情况下处理器检测到未对齐的内存操作；
* `#XF` - SIMD Floating-Point， 在处理器检测到`SSE`、`SSE2`或`SSE3` SIMD 浮点异常时触发；在执行SIMD浮点指令时，有6类数字异常会触发该类异常，包括：Invalid operation，Divide-by-zero, Denormal operand, Numeric overflow, Numeric underflow, Inexact result (Precision);
* `#DF` - Double Fault, 在处理器在调用前一个异常处理时检测到第二个异常时触发。通常，当处理器在尝试调用异常处理程序时检测到另一个异常，可以串行处理这两个异常。如果，处理器不能串行处理它们，会触发双重故障异常。
* `#MC` - Machine-Check，该异常取决于`CONFIG_X86_MCE`内核配置选项，在检测到内部[机器错误, Machine error](https://en.wikipedia.org/wiki/Machine-check_exception)或总线错误，或者外部代理检测到总线错误时触发该异常；
* `#OF` - Overflow，在一个特殊的`INTO`指令执行时，触发该异常；
* `#SYSCALL` - IA32系统调用（`0x80`）中断，该中断实现取决于内核配置选项，在`x86_64`下使用`CONFIG_IA32_EMULATION`内核配置选项，使用`entry_INT80_compat`中断函数；在`x86_32`下使用`CONFIG_X86_32`内核配置选项，使用`entry_INT80_32`中断函数；

### 2.2 CPU及寄存器设置

* 映射IDT描述符

接下来，我们映射IDT描述符到固定的只读区域，如下：

```C
	cea_set_pte(CPU_ENTRY_AREA_RO_IDT_VADDR, __pa_symbol(idt_table),
		    PAGE_KERNEL_RO);
	idt_descr.address = CPU_ENTRY_AREA_RO_IDT;
```

* CPU初始化
  
接下来，我们调用`cpu_init`函数，在[arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/common.c#L1266)中实现，该函数初始化所有的`per-cpu`状态。

在`cpu_init`函数的开始，我们等待当前CPU初始化完成后，必要时加载微代码，如下：

```C
	wait_for_master_cpu(cpu);
	if (cpu)
		load_ucode_ap();
```

* 获取TSS

接下来，我们获取当前CPU的任务状态段（Task State Segment， TSS），如下：

```C
	t = &per_cpu(cpu_tss_rw, cpu);
```

* `cr4`寄存器设置

清除`cr4`寄存器状态，禁用`vm86`扩展、虚拟中断、时间戳（[RDTSC](https://en.wikipedia.org/wiki/Time_Stamp_Counter)只能在最高权限下使用）和调试扩展， 如下：

```C
	cr4_clear_bits(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);
```

* 重新加载GDT和IDT

如下：

```C
	switch_to_new_gdt(cpu);
	loadsegment(fs, 0);
	load_current_idt();
```

* CPU其他设置

接下来，我们设置线程本地存储描述符（TLS）数组，初始化系统调用，设置NX执行位，加载微代码。如下：

```C
	memset(me->thread.tls_array, 0, GDT_ENTRY_TLS_ENTRIES * 8);
	syscall_init();

	wrmsrl(MSR_FS_BASE, 0);
	wrmsrl(MSR_KERNEL_GS_BASE, 0);
	barrier();

	x86_configure_nx();
	x2apic_setup();
```

* 填充IST堆栈

在ist没有初始化时，填充ist对应的栈地址，如下：

```C
	if (!t->x86_tss.ist[0]) {
		t->x86_tss.ist[IST_INDEX_DF] = __this_cpu_ist_top_va(DF);
		t->x86_tss.ist[IST_INDEX_NMI] = __this_cpu_ist_top_va(NMI);
		t->x86_tss.ist[IST_INDEX_DB] = __this_cpu_ist_top_va(DB);
		t->x86_tss.ist[IST_INDEX_MCE] = __this_cpu_ist_top_va(MCE);
	}
```

在填充Task State Segments（TSS）的Interrupt Stack Tables（IST）后，我们重新设置并加载当前CPU的TSS描述符，如下：

```C
	set_tss_desc(cpu, &get_cpu_entry_area(cpu)->tss.x86_tss);
	load_TR_desc();
	load_sp0((unsigned long)(cpu_entry_stack(cpu) + 1));
```

`set_tss_desc`宏在[arch/x86/include/asm/desc.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/desc.h#L184)中定义，将指定描述符写入到给定CPU的GDT中，如下：

```C
#define set_tss_desc(cpu, addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)

static inline void __set_tss_desc(unsigned cpu, unsigned int entry, struct x86_hw_tss *addr)
{
	struct desc_struct *d = get_cpu_gdt_rw(cpu);
	tss_desc tss;

	set_tssldt_descriptor(&tss, (unsigned long)addr, DESC_TSS,
			      __KERNEL_TSS_LIMIT);
	write_gdt_entry(d, entry, &tss, DESC_TSS);
}
```

`load_TR_desc`宏定义展开后为`ltr`（Load Task Register），如下：

```C
#define load_TR_desc()				native_load_tr_desc()

static inline void native_load_tr_desc(void)
{
	asm volatile("ltr %w0"::"q" (GDT_ENTRY_TSS*8));
}
```

`load_sp0`设置TSS的sp0，sp0指向trampoline栈，如下：

```C
static inline void load_sp0(unsigned long sp0)
{
	native_load_sp0(sp0);
}

static inline void
native_load_sp0(unsigned long sp0)
{
	this_cpu_write(cpu_tss_rw.x86_tss.sp0, sp0);
}
```

### 2.3 陷阱门IST设置（`idt_setup_ist_traps`）

调用`idt_setup_ist_traps`函数设置中断的IST堆栈，设置过程同其他中断设置函数一样，通过`ist_idts`中断表来设置IST堆栈，定义如下：

```C
static const __initconst struct idt_data ist_idts[] = {
	ISTG(X86_TRAP_DB,	debug,		IST_INDEX_DB),
	ISTG(X86_TRAP_NMI,	nmi,		IST_INDEX_NMI),
	ISTG(X86_TRAP_DF,	double_fault,	IST_INDEX_DF),
#ifdef CONFIG_X86_MCE
	ISTG(X86_TRAP_MC,	&machine_check,	IST_INDEX_MCE),
#endif
};
```

`ISTG`宏和`INTG`宏不同的地方在于`INTG`使用默认堆栈，`ISTG`使用设置的堆栈。这里，我们重新设置这几个中断，是因为在`cpu_init`函数执行前，TSS还没有初始化。

### 2.4 调试陷阱门设置（`idt_setup_debugidt_traps`）

在这里，我们复制`idt_table`到`debug_idt_table`，并设置`#DB`中断处理函数。如下：

```C
void __init idt_setup_debugidt_traps(void)
{
	memcpy(&debug_idt_table, &idt_table, IDT_ENTRIES * 16);

	idt_setup_from_table(debug_idt_table, dbg_idts, ARRAY_SIZE(dbg_idts), false);
}
```

## 3 结束语

本文描述了`#PF`中断的实现过程；不同中断处理程序的设置过程，如：`#DE`,`#NIM`等；任务状态段（Task State Segment， TSS）的初始化过程；调试IDT的设置过程等内容。在本文，我们仅仅描述了中断初始化内容，在接下来的章节中，我们将深入这些中断处理程序的实现细节。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
