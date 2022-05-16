# 内核系统调用 （第二部分）

## 0 介绍

在前一部分中描述了Linux内核[system call](https://en.wikipedia.org/wiki/System_call)概念。我们从用户空间的角度介绍了Linux内核中的系统调用，并且介绍了[write](http://man7.org/linux/man-pages/man2/write.2.html)系统调用实现。本文继续关注系统调用，在深入Linux内核之前，从一些理论开始。

用户程序并不直接使用系统调用。我们并不会这样写 `Hello World`程序代码：

```C
int main(int argc, char **argv)
{
	...
	sys_write(fd1, buf, strlen(buf));
	...
}
```

我们可以借助[C标准库](https://en.wikipedia.org/wiki/GNU_C_Library)来实现，如下:

```C
#include <unistd.h>

int main(int argc, char **argv)
{
	...
	write(fd1, buf, strlen(buf));
	...
}
```

不管怎样，`write`函数不是直接的系统调用也不是内核函数。程序必须将通用寄存器按照正确的顺序存入正确的值，之后使用`syscall`指令实现真正的系统调用。接下来，我们将深入分析Linux内核中处理器执行`syscall`指令时的细节。

## 1 系统调用表的初始化

从前一部分中可以知道系统调用与中断非常相似。深入的说，系统调用是软件中断的处理程序。因此，当处理器执行用户程序的`syscall`指令时，指令引起异常导致将控制权转移至异常处理。众所周知，所有的异常处理(或者内核 [C](https://en.wikipedia.org/wiki/C_%28programming_language%29) 函数将响应异常)是放在内核代码中的。

但是Linux内核如何查找系统调用对应的系统调用处理程序的地址？这是通过Linux内核中由一个特殊的系统调用表（system call table）来实现的。系统调用表在[arch/x86/entry/syscall_64.c](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscall_64.c)中定义，如下:

```C
asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	[0 ... __NR_syscall_max] = &__x64_sys_ni_syscall,
#include <asm/syscalls_64.h>
};
```

可以看到，`sys_call_table`数组的大小为`__NR_syscall_max + 1`， `__NR_syscall_max`宏表示指定[CPU架构](https://en.wikipedia.org/wiki/List_of_CPU_architectures)中系统调用最大数量。[x86_64](https://en.wikipedia.org/wiki/X86-64)架构下`__NR_syscall_max` 为`435`，是当前`5.4.148`内核版本的数量。编译内核时可通过[Kbuild](https://www.kernel.org/doc/Documentation/kbuild/makefiles.txt)产生的`include/generated/asm-offsets.h`头文件查看该宏的定义:

```C
#define __NR_syscall_max 435 /* sizeof(syscalls_64) - 1 */
```

对于`x86_64`，在[arch/x86/entry/syscalls/syscall_64.tbl](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscall_64.tbl#L359)中也有相同的系统调用数量。这里存在两个重要的话题： `sys_call_table` 数组的类型及数组中元数的初始值。首先，`sys_call_ptr_t` 为指向系统调用表的指针，在[arch/x86/include/asm/syscall.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/syscall.h#L21)中定义，如下：

```C
#ifdef CONFIG_X86_64
typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
#else
typedef asmlinkage long (*sys_call_ptr_t)(unsigned long, unsigned long,
					  unsigned long, unsigned long,
					  unsigned long, unsigned long);
#endif /* CONFIG_X86_64 */
```

其次为 `sys_call_table` 数组中元素的初始化，从上面的代码中可知，数组中所有元素包含指向 `__x64_sys_ni_syscall` 的系统调用处理器的指针。`__x64_sys_ni_syscall`通过`SYSCALL_DEFINE0`来定义，调用`sys_ni_syscall`。如下：

```C
SYSCALL_DEFINE0(ni_syscall)
{
	return sys_ni_syscall();
}
```

`sys_ni_syscall` 函数为 “not-implemented” 调用，在[kernel/sys_ni.c](https://github.com/torvalds/linux/blob/v5.4/kernel/sys_ni.c#L20)中实现，该函数比较简单, 仅仅返回`-ENOSYS`的[errno](http://man7.org/linux/man-pages/man3/errno.3.html)，如下:

```C
asmlinkage long sys_ni_syscall(void)
{
	return -ENOSYS;
}
```

`ENOSYS`在[include/uapi/asm-generic/errno.h](https://github.com/torvalds/linux/blob/v5.4/include/uapi/asm-generic/errno.h#L18)定义，表示无效的系统调用。如下：

```C
#define	ENOSYS		38	/* Invalid system call number */
```

在 `sys_call_table` 的初始化中同时也要注意 `...` 。可通过 [GCC](https://en.wikipedia.org/wiki/GNU_Compiler_Collection) 编译器的[Designated Initializers](https://gcc.gnu.org/onlinedocs/gcc/Designated-Inits.html)插件来处理，插件允许使用非固定的顺序初始化元素。在数组结束处，我们引用`asm/syscalls_64.h`头文件在。头文件由特殊的脚本[arch/x86/entry/syscalls/syscalltbl.sh](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscalltbl.sh)从[syscall table](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscall_64.tbl)产生。`arch/x86/include/generated/asm/syscalls_64.h`包括以下宏的定义:

```C
#ifdef CONFIG_X86
__SYSCALL_64(0, __x64_sys_read, )
#else /* CONFIG_UML */
__SYSCALL_64(0, sys_read, )
#endif
#ifdef CONFIG_X86_X32_ABI
__SYSCALL_X32(0, __x64_sys_read, )
#endif
#ifdef CONFIG_X86
__SYSCALL_64(1, __x64_sys_write, )
#else /* CONFIG_UML */
__SYSCALL_64(1, sys_write, )
#endif
#ifdef CONFIG_X86_X32_ABI
__SYSCALL_X32(1, __x64_sys_write, )
#endif
...
...
...
```

`__SYSCALL_64`宏在[arch/x86/entry/syscall_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscall_64.c#L18)中定义，如下：

```C
#define __SYSCALL_64(nr, sym, qual) extern asmlinkage long sym(const struct pt_regs *);
#define __SYSCALL_X32(nr, sym, qual) __SYSCALL_64(nr, sym, qual)
#include <asm/syscalls_64.h>
#undef __SYSCALL_64
#undef __SYSCALL_X32

#define __SYSCALL_64(nr, sym, qual) [nr] = sym,
#define __SYSCALL_X32(nr, sym, qual)
```

可以看到，前一个`__SYSCALL_64`宏定义函数，后一个宏进行初始化。到此为止, `sys_call_table` 初始化如下:

```C
asmlinkage const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	[0 ... __NR_syscall_max] = &__x64_sys_ni_syscall,
	[0] = __x64_sys_read,
	[1] = __x64_sys_write,
	[2] = __x64_sys_open,
	...
	...
	...
};
```

在此之后，所有指向未实现的系统调用元素指向`sys_ni_syscall`函数的地址，该函数仅返回`-ENOSYS`。其他元素指向`sys_syscall_name`函数。

至此, 我们已经完成了系统调用表的填充，Linux内核知道每个系统调用处理程序的位置。但是Linux内核在处理用户空间程序的系统调用时并不会立即调用 `sys_syscall_name` 函数。关于中断及中断处理的章节中，当 Linux 内核获得处理中断的控制权, 在调用中断处理程序前，必须做一些准备如保存用户空间寄存器，切换至新的堆栈及其他很多工作。系统调用处理也是相同的情形，第一件事是处理系统调用的准备，但是在 Linux 内核开始这些准备之前, 系统调用的入口必须完成初始化，同时只有 Linux 内核知道如何执行这些准备。接下来，我们将关注 Linux 内核中关于系统调用入口的初始化过程。

## 2 系统调用入口初始化

当系统中发生系统调用, 开始处理调用的代码的第一个字节在什么地方? 通过阅读 Intel 的手册[64-ia-32-architectures-software-developer-vol-2b-manual](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)可以看到:

```text
SYSCALL调用操作系统系统调用时处理器处于特权级0，通过加载IA32_LSTAR MSR至RIP来实现。
```

这就是说我们需要将系统调用入口放置到 `IA32_LSTAR`[model specific register](https://en.wikipedia.org/wiki/Model-specific_register)寄存器中，该操作在 Linux 内核初始过程时完成。Linux内核调用在初始化过程中调用 `trap_init` 函数，该函数在[arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/traps.c#L925)文件中定义，完成非早期异常处理（如除法错误，[协处理器](https://en.wikipedia.org/wiki/Coprocessor)错误等）的初始化，除此之外，调用[arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/master/blob/arch/x86/kernel/cpu/common.c)中`cpu_init`函数。`cpu_init`函数调用同一个文件中的`syscall_init`函数来完成系统调用初始化，如下：

```C
void syscall_init(void)
{
	wrmsr(MSR_STAR, 0, (__USER32_CS << 16) | __KERNEL_CS);
	wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
	...
	...
}
```

可以看到，该函数首先通过填充MSR寄存器来实现系统调用的入口初始化。

* `MSR_STAR`寄存器 -- `63:48`为用户代码的代码段，在执行`sysret`指令从系统调用返回到用户代码时，当这些数据将加载至`CS`和`SS`段选择符寄存器中。同时，`MSR_STAR`还包含内核代码位，当用户空间应用程序执行系统调用时，`47:32`将作为`CS`和`SS`段选择寄存器的基地址。
* `MSR_LSTAR`寄存器 -- 系统调用的函数，使用`entry_SYSCALL_64`填充。`entry_SYSCALL_64`在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L145)汇编文件中定义。

在设置系统调用的入口之后，需要以下特殊模式寄存器：

* `MSR_CSTAR` --  兼容模式调用时，`rip`寄存器的值；
* `MSR_IA32_SYSENTER_CS` -- `sysenter`指令调用时，`cs`寄存器的值；
* `MSR_IA32_SYSENTER_ESP` -- `sysenter`指令调用时，`esp`寄存器的值；
* `MSR_IA32_SYSENTER_EIP` -- `sysenter`指令调用时，`eip`寄存器的值。

这些特殊模式寄存器的值与`CONFIG_IA32_EMULATION`内核配置选项有关。若开启该内核配置选项，表示允许64位内核运行32位的程序。`CONFIG_IA32_EMULATION`内核配置选项开启时, 将使用兼容模式的系统调用入口填充这些特殊模式寄存器，对于内核代码段, 将堆栈指针置零，`entry_SYSENTER_compat`字的地址写入[指令指针](https://en.wikipedia.org/wiki/Program_counter)，如下：

```C
	wrmsrl(MSR_CSTAR, (unsigned long)entry_SYSCALL_compat);
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)__KERNEL_CS);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP,
		    (unsigned long)(cpu_entry_stack(smp_processor_id()) + 1));
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, (u64)entry_SYSENTER_compat);
```

若`CONFIG_IA32_EMULATION`内核配置选项未开启, 将把`ignore_sysret`写入`MSR_CSTAR`：

```C
wrmsrl(MSR_CSTAR, ignore_sysret);
```

`ignore_sysret`在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L1728)汇编文件中定义，仅返回 `-ENOSYS` 错误代码:

```assembly
ENTRY(ignore_sysret)
	UNWIND_HINT_EMPTY
	mov	$-ENOSYS, %eax
	sysret
END(ignore_sysret)
```

将`MSR_IA32_SYSENTER_ESP` 和 `MSR_IA32_SYSENTER_EIP`用零填充，`MSR_IA32_SYSENTER_CS` 用无效的[Global Descriptor Table](https://en.wikipedia.org/wiki/Global_Descriptor_Table)填充，如下：

```C
wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)GDT_ENTRY_INVALID_SEG);
wrmsrl_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
wrmsrl_safe(MSR_IA32_SYSENTER_EIP, 0ULL);
```

在`syscall_init`函数的结束, 写入`MSR_SYSCALL_MASK`特殊寄存器的标志位，将[标志寄存器](https://en.wikipedia.org/wiki/FLAGS_register)中的标志位屏蔽:

```C
wrmsrl(MSR_SYSCALL_MASK,
	   X86_EFLAGS_TF|X86_EFLAGS_DF|X86_EFLAGS_IF|
	   X86_EFLAGS_IOPL|X86_EFLAGS_AC|X86_EFLAGS_NT);
```

这些标志位将在`syscall`初始化时清除。至此，`syscall_init`函数结束，也意味着系统调用已经可用。现在我们关注当用户程序执行 `syscall` 指令发生什么。

## 3 系统调用的执行过程

如之前写到，在Linux内核调用系统调用或中断处理之前需要一些准备，`idtentry`宏进行异常处理执行前的准备，`interrupt`宏进行中断处理调用前的准备，同样的，`entry_SYSCALL_64`宏进行系统调用执行前的准备。

`entry_SYSCALL_64`在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L145)文件中定义，如下：

### 3.1 切换栈空间

```C
ENTRY(entry_SYSCALL_64)
	UNWIND_HINT_EMPTY
	swapgs
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp
```

`swapgs`指令将交换`GS`段选择符及`MSR_KERNEL_GS_BASE`寄存器中的值。换句话说，将其入内核堆栈。之后保存栈顶`rsp`寄存器到`cpu_tss_rw`；切换到内核空间；设置堆栈指针指向当前处理器的栈顶。

### 3.2 保存寄存器值

接下来，在栈空间上构建`pt_regs`结构，保存通用寄存器值，如下：

```C
	pushq	$__USER_DS				/* pt_regs->ss */
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)	/* pt_regs->sp */
	pushq	%r11					/* pt_regs->flags */
	pushq	$__USER_CS				/* pt_regs->cs */
	pushq	%rcx					/* pt_regs->ip */
GLOBAL(entry_SYSCALL_64_after_hwframe)
	pushq	%rax					/* pt_regs->orig_ax */

	PUSH_AND_CLEAR_REGS rax=$-ENOSYS
```

在调用`PUSH_AND_CLEAR_REGS`保存通用寄存器值时，将`rax`设置为`-ENOSYS`。当用户空间进行系统调用时, 通用目的寄存器状态如下:

* `rax` - 系统调用号;
* `rcx` - 返回用户空间的地址;
* `r11` - 寄存器标志;
* `rdi` - 系统调用处理程序的第一个参数;
* `rsi` - 系统调用处理程序的第二个参数;
* `rdx` - 系统调用处理程序的第三个参数;
* `r10` - 系统调用处理程序的第四个参数;
* `r8`  - 系统调用处理程序的第五个参数;
* `r9`  - 系统调用处理程序的第六个参数;

其他的寄存器(如：`rbp`, `rbx`和`r12` ~ `r15`)保留。

### 3.3 执行系统调用

接下来，禁用`IRQ`，构建执行系统调用函数栈，并调用`do_syscall_64`函数。

```C
	TRACE_IRQS_OFF

	/* IRQs are off. */
	movq	%rax, %rdi
	movq	%rsp, %rsi
	call	do_syscall_64		/* returns with IRQs disabled */

	TRACE_IRQS_IRETQ		/* we're about to change IF */
```

`do_syscall_64`函数在[arch/x86/entry/common.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/common.c#L278)中定义，需要两个参数：`nr` -- 系统调用号; `regs` -- 寄存器指针。如下：

```C
__visible void do_syscall_64(unsigned long nr, struct pt_regs *regs)
{
	struct thread_info *ti;

	enter_from_user_mode();
	local_irq_enable();
	ti = current_thread_info();
	if (READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY)
		nr = syscall_trace_enter(regs);

	if (likely(nr < NR_syscalls)) {
		nr = array_index_nospec(nr, NR_syscalls);
		regs->ax = sys_call_table[nr](regs);
	}
	...
	...
	syscall_return_slowpath(regs);
}
```

`enter_from_user_mode`函数和`syscall_trace_enter`函数用于系统调用追踪，这里不进行讨论。`local_irq_enable`启用本地中断。在此之后，获取到对应的系统调用号后，调用响应的执行函数，如下：

```C
		nr = array_index_nospec(nr, NR_syscalls);
		regs->ax = sys_call_table[nr](regs);
```

在`x86_64`架构平台下，`__SYSCALL_DEFINEx`在[arch/x86/include/asm/syscall_wrapper.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/syscall_wrapper.h#L157)中定义，使用`pt_regs`结构保存系统中断参数。定义了`__x64_sys##name(const struct pt_regs *regs)`，`__se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))` 和 `__do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))`三个函数。`__x64_sys##name`函数中通过`SC_X86_64_REGS_TO_ARGS`宏将`pt_regs`转换为函数对应的参数。如下：

```C
#define SC_X86_64_REGS_TO_ARGS(x, ...)					\
	__MAP(x,__SC_ARGS						\
		,,regs->di,,regs->si,,regs->dx				\
		,,regs->r10,,regs->r8,,regs->r9)			\

	asmlinkage long __x64_sys##name(const struct pt_regs *regs)	\
	{								\
		return __se_sys##name(SC_X86_64_REGS_TO_ARGS(x,__VA_ARGS__));\
	}			
```

这样，系统调用处理将被相应的处理调用。例如：Linux内核代码中`SYSCALL_DEFINE[N]`宏定义的 `sys_read`, `sys_write` 和其他处理。

在`do_syscall_64`函数的最后，调用`syscall_return_slowpath`函数，该函数在同一个文件中定义，如下：

```C
__visible inline void syscall_return_slowpath(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	u32 cached_flags = READ_ONCE(ti->flags);

	CT_WARN_ON(ct_state() != CONTEXT_KERNEL);

	if (IS_ENABLED(CONFIG_PROVE_LOCKING) &&
	    WARN(irqs_disabled(), "syscall %ld left IRQs disabled", regs->orig_ax))
		local_irq_enable();

	rseq_syscall(regs);

	if (unlikely(cached_flags & SYSCALL_EXIT_WORK_FLAGS))
		syscall_slow_exit_work(regs, cached_flags);

	local_irq_disable();
	prepare_exit_to_usermode(regs);
}
```

该函数调用`rseq_syscall`函数判断系统调用是否正常，如果调用出错，发送`SIGSEGV`信号终止程序。调用正常时进行系统调用的清理工作，包括：`local_irq_disable`禁用本地中断，`prepare_exit_to_usermode`返回到用户空间的准备工作。

### 3.4 退出系统调用

在系统调用处理完成后, 返回到[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L177)位置继续执行，如下：

```C
	TRACE_IRQS_IRETQ		/* we're about to change IF */

	movq	RCX(%rsp), %rcx
	movq	RIP(%rsp), %r11

	cmpq	%rcx, %r11	/* SYSRET requires RCX == RIP */
	jne	swapgs_restore_regs_and_return_to_usermode

#ifdef CONFIG_X86_5LEVEL
	ALTERNATIVE "shl $(64 - 48), %rcx; sar $(64 - 48), %rcx", \
		"shl $(64 - 57), %rcx; sar $(64 - 57), %rcx", X86_FEATURE_LA57
#else
	shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
	sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
#endif

	cmpq	%rcx, %r11
	jne	swapgs_restore_regs_and_return_to_usermode
	...
	...
```

首先，执行`TRACE_IRQS_IRETQ`恢复IRQ追踪；恢复`rcx`和`r11`寄存器值。在此之后，通过判断`rcx`和`r11`寄存器值、`CS`寄存器值等条件，判断是否进行跳转，所有的跳转均跳转到`swapgs_restore_regs_and_return_to_usermode`标签。通过标签名称可以知道，该标签进行一系列操作，包括：切换`gs`，恢复通用寄存器值后返回到用户空间。如下：

```C
GLOBAL(swapgs_restore_regs_and_return_to_usermode)
	...
	POP_REGS pop_rdi=0

	movq	%rsp, %rdi
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
	UNWIND_HINT_EMPTY

	pushq	6*8(%rdi)	/* SS */
	pushq	5*8(%rdi)	/* RSP */
	pushq	4*8(%rdi)	/* EFLAGS */
	pushq	3*8(%rdi)	/* CS */
	pushq	2*8(%rdi)	/* RIP */

	pushq	(%rdi)

	STACKLEAK_ERASE_NOCLOBBER

	SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi

	popq	%rdi
	SWAPGS
	INTERRUPT_RETURN
```

整个退出过程如下：调用`POP_REGS`恢复通用寄存器值；恢复`rsp`, `ss`, `eflags`, `cs`, `rip`等寄存器值；`SWITCH_TO_USER_CR3_STACK`切换到用户页表；执行`SWAPGS`切换`gs`，此时，栈空间为用户栈空间；最后，执行`INTERRUPT_RETURN`（即：`iret`）指令跳转返回。

现在我们知道，当用户程序使用系统调用时发生的一切。整个过程的步骤如下：

* 用户程序中的代码装入通用目的寄存器的值（系统调用编号和系统调用的参数）;
* 处理器从用户模式切换到内核模式 开始执行系统调用入口 - `entry_SYSCALL_64`;
* `entry_SYSCALL_64` 切换至内核堆栈，在堆栈中存通用寄存器, 老的堆栈，代码段, 标志位等;
* 调用`do_syscall_64`函数，执行系统调用。通过`rax`寄存器中的系统调用编号，在 `sys_call_table` 中查找系统调用处理并调用;
* 系统调用处理完成工作后, 恢复通用寄存器, 老的堆栈，标志位 及返回地址，通过`iret` 指令退出`entry_SYSCALL_64`。

## 4 结束语

上一篇中从用户应用程序的角度讨论了系统调用的原理。本文在前文的基础上，讨论了系统调用发生时 Linux 内核执行的过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
