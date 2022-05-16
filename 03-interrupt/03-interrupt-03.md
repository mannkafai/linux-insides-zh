# 中断和中断处理 （第三部分）

## 0 中断和异常处理过程

在上一部分，我们在`setup_arch`函数中调用`idt_setup_early_traps`函数设置了`#DB`和`#BP`这两个中断处理函数。接下来，我们分析其实现过程。

## 1 调试和断点介绍

`idt_setup_early_traps`函数设置了`#DB`和`#BP`这两个中断处理函数，首先，我们需要了解一些基本的概念。

`#DB`（调试）异常在调试事件发生时触发，比如，修改[调试寄存器（debug register）](http://en.wikipedia.org/wiki/X86_debug_register)的内容。调试
寄存器是从`Intel 80386`处理器开始添加的特殊寄存器，从名字上可以很容易理解，这些寄存器主要用于调试。这些寄存器允许在代码上设置断点并读取或写入数据以追踪它。调试寄存器只允许在特权模式下访问，任何其他特权级别在执行时尝试读取或写入调试寄存器时，会导致[保护错误（General protection fault）](https://en.wikipedia.org/wiki/General_protection_fault)异常。因此，我们没有将其设置系统中断。

`#DB`（调试）的中断向量编号是`1`（即，`X86_TRAP_DB`），正如我们在规范文档中说明的那样，该异常没有错误代码：

```text
+-----------------------------------------------------+
|Vector|Mnemonic|Description         |Type |Error Code|
+-----------------------------------------------------+
|1     | #DB    |Reserved            |F/T  |NO        |
+-----------------------------------------------------+
```

`#BP`（断点）异常在处理器执行[int 3](https://en.wikipedia.org/wiki/INT_(x86_instruction)#INT_3)指令时触发。`#BP`异常可能发生在用户空间，我们可能在任何时候触发，让我们来看下面简单的示例：

```C
// breakpoint.c
#include <stdio.h>

int main() {
    int i;
    while (i < 6){
        printf("i equal to: %d\n", i);
        __asm__("int3");
        ++i;
    }
}
```

我们编译、运行这个程序后，可以看到下面的输出：

```bash
$ gcc breakpoint.c -o breakpoint
i equal to: 0
Trace/breakpoint trap
```

但是，我们通过gdb运行，可以看到断点信息，并能够继续执行我们的程序。如下：

```bash
$ gdb breakpoint
...
...
...
(gdb) run
Starting program: /home/alex/breakpoints 
i equal to: 0

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:    83 45 fc 01    add    DWORD PTR [rbp-0x4],0x1
(gdb) c
Continuing.
i equal to: 1

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:    83 45 fc 01    add    DWORD PTR [rbp-0x4],0x1
(gdb) c
Continuing.
i equal to: 2

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0000000000400585 in main ()
=> 0x0000000000400585 <main+31>:    83 45 fc 01    add    DWORD PTR [rbp-0x4],0x1
...
...
...
```

## 2 中断处理前的准备（`idtentry`宏）

在上一节中，通过`INTG`和`SYSG`宏生成`idt_data`信息时，需要两个参数（即，中断向量号和中断处理函数地址）。在当期的情况下，这两个中断处理函数是`debug`和`int3`。我们没有在C代码中找到这些函数的定义，在所有的`*.c/*.h`文件中，我们在[arch/x86/include/asm/traps.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/traps.h#L14)文件中找到相关定义，如下：

```C
asmlinkage void debug(void);
asmlinkage void int3(void);
```

在这些函数前有个`asmlinkage`的修饰命令，这是gcc编译器的特殊说明符，在从汇编代码调用C函数时，我们需要显示指定函数调用约定。当我们使用`asmlinkage`描述符时，gcc在编译程序时从栈上获取参数。

同其他处理函数一样，`#DB`和`#BP`中断处理函数在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L1192)中实现。如下：

```C
idtentry debug  do_debug    has_error_code=0    paranoid=1 shift_ist=IST_INDEX_DB ist_offset=DB_STACK_OFFSET
idtentry int3   do_int3 has_error_code=0    create_gap=1
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
    _ASM_NOKPROBE(\sym)
END(\sym)
.endm
```

`idtentry`支持8个参数：

* sym - 中断条目名称；
* do_sym - 中断处理程序的C函数；
* has_error_code - 在栈上是否有中断错误码；
* paranoid - 如果非零，表示在内核空间；
* shift_ist - IST切换栈的次数，在切换栈时递减。为`#DB`特殊设置的，可能会出现递归栈。
* ist_offset - IST的偏移量；
* create_gap - 从内核模式切换时是否创建6个字的栈间隔；
* read_cr2 - 在调用C函数前，是否加载`cr2`寄存器值到第三个参数；

在我们深入`idtentry`宏的内部之前，我们应该知道异常发生时堆栈的状态。异常发生时的栈状态如下：

```C
    +------------+
+40 | %SS        |
+32 | %RSP       |
+24 | %RFLAGS    |
+16 | %CS        |
 +8 | %RIP       |
  0 | ERROR CODE | <-- %RSP
    +------------+
```

通过`#DB`和`#BP`的定义，我们知道编译器将生成两个中断处理程序`debug`和`int3`，这两个异常处理程序都将在经过一些准备后调用`do_debug`和`do_int3`处理程序。接下来，我们看下其实现过程：

### 2.1 输入参数检查

首先，中断处理函数输入参数的正确性，如下：

```C
    /* Sanity check */
    .if \shift_ist != -1 && \paranoid != 1
    .error "using shift_ist requires paranoid=1"
    .endif

    .if \create_gap && \paranoid
    .error "using create_gap requires paranoid=0"
    .endif
```

### 2.2 检查错误码

检查是否有错误码(`has_error_code`)，无错误码时将`-1`压入栈中，如下：

```C
    .if \has_error_code == 0
    pushq    $-1                /* ORIG_RAX: no syscall to restart */
    .endif
```

正如我们在上图中可以看到的，如果异常提供了错误代码，处理器会将错误代码推送到堆栈上。如果异常没有错误代码。这可能会带来一些困难，因为堆栈对于提供错误代码的异常和不提供错误代码的异常看起来会有所不同。因此，`idtentry`宏在没有异常时，从将假错误代码（即，-1）放入堆栈开始位置。`-1`不仅仅是假的错误代码，也代表无效的系统调用号，这样系统调用重启逻辑就不会被触发。

### 2.3 检查是否切换堆栈

`idtentry`宏的`shift_ist`和`paranoid`两个参数判断是否在`Interrupt Stack Table`堆栈中运行异常处理程序。系统中的每个内核线程都有自己的堆栈，除了这些堆栈之外，还有一些与系统中的每个处理器相关联的专用堆栈，其中一个是异常堆栈。`x86_64`架构提供了特殊的功能，称为`Interrupt Stack Table`，这个功能允许为指定事件（例如`double fault`等）切换到新堆栈。`shift_ist`参数表示将异常处理程序切换到IST堆栈。

`paranoid`参数表示中断处理程序是否来自用户空间，确定这一点的最简单方法是通过在CS段寄存器中权限等级（CPL，Current Privilege Level）。如果等于3，我们来自用户空间，如果为零，我们来自内核空间。

```C
    .if \paranoid == 1
    testb   $3, CS-ORIG_RAX(%rsp)       /* If coming from userspace, switch stacks */
    jnz .Lfrom_usermode_switch_stack_\@
    .endif
```

当中断处理程序来自用户空间时，跳转到`from_usermode_switch_stack_`执行，如下：

```C
.Lfrom_usermode_switch_stack_\@:
    idtentry_part \do_sym, \has_error_code, \read_cr2, paranoid=0
    .endif
```

但是，这种方法并不能提供100%的保证。如内核文档中所述：

```text
如果我们处于NMI/MCE/DEBUG/任何超​​原子条目上下文中，这可能在正常条目将`CS`写入堆栈之后，在执行`SWAPGS`之前立即触发，那么检查`GS`的唯一安全方法是速度较慢方法：`RDMSR`。
```

换句话说，`NMI`可能发生在[SWAPGS](https://www.felixcloutier.com/x86/swapgs)指令临界区之间。这样，我们应该检查存储在perCPU区域开始位置的[Model specific register](https://en.wikipedia.org/wiki/Model-specific_register) 寄存器（即，`MSR_GS_BASE`）的值。所以要检查我们是否来自用户空间，我们应该检查`MSR_GS_BASE`寄存器的值，如果它是负数，我们来自内核空间，否则我们来自用户空间，如下：

```C
    movl    $MSR_GS_BASE, %ecx
    rdmsr
    testl    %edx, %edx
    js    1f                /* negative -> in kernel */
    SWAPGS
```

### 2.4 检查是否创建间隔

`create_gap`表示是否创建间隔。在内核空间下，创建6个字的间隔用于`int3`中断处理模拟调用指令。如果来自用户空间时，跳转到`from_usermode_no_gap_`执行。如下：

```C
    .if \create_gap == 1
    testb    $3, CS-ORIG_RAX(%rsp)
    jnz    .Lfrom_usermode_no_gap_\@
    .rept    6
    pushq    5*8(%rsp)
    .endr
    UNWIND_HINT_IRET_REGS offset=8
.Lfrom_usermode_no_gap_\@:
    .endif

    idtentry_part \do_sym, \has_error_code, \read_cr2, \paranoid, \shift_ist, \ist_offset
```

### 2.5 调用`idtentry_part`宏

经过上面两部判断后，可以看到，最终调用的是`idtentry_part`。

## 3 用户空间的中断处理过程（`idtentry_part`）

`idtentry_part`宏也在同一个文件中定义，在`idtentry`的基础上实现中断处理过程。如下：

```C
.macro idtentry_part do_sym, has_error_code:req, read_cr2:req, paranoid:req, shift_ist=-1, ist_offset=0

    .if \paranoid
    call    paranoid_entry
    /* returned flag: ebx=0: need swapgs on exit, ebx=1: don't need it */
    .else
    call    error_entry
    .endif
    UNWIND_HINT_REGS

...
.endm
```

`idtentry_part`支持6个参数：

* do_sym - 中断处理程序的C函数；
* has_error_code - 在栈上是否有中断错误码；
* paranoid - 如果非零，表示在内核空间；
* shift_ist - IST切换栈的次数，在切换栈时递减。为`#DB`特殊设置的，可能会出现递归栈。
* ist_offset - IST的偏移量；
* read_cr2 - 在调用C函数前，是否加载`cr2`寄存器值到第三个参数；

`idtentry_part`的执行过程如下：

### 3.1 按需切换内核栈空间

首先，检查`paranoid`参数，`paranoid > 0`时，表示中断发生在内核空间，调用`paranoid_entry`宏，否则，中断发生在用户空间，调用`error_entry`宏。如下：

```C
    .if \paranoid
    call    paranoid_entry
    /* returned flag: ebx=0: need swapgs on exit, ebx=1: don't need it */
    .else
    call    error_entry
    .endif
```

现在，我们首先考虑第一种情况，来自用户空间到中断处理的过程，即，调用`error_entry`宏。`error_entry`宏也在同一个文件中定义，如下：

```C
ENTRY(error_entry)
    UNWIND_HINT_FUNC
    cld
    PUSH_AND_CLEAR_REGS save_ret=1
    ENCODE_FRAME_POINTER 8
    testb    $3, CS+8(%rsp)
    jz    .Lerror_kernelspace
    ...
END(error_entry)
```

#### 3.1.1 保存通用寄存器值

首先，调用`PUSH_AND_CLEAR_REGS`宏保存通用寄存器值，`PUSH_AND_CLEAR_REGS`宏在[arch/x86/entry/calling.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/calling.h#L100)中实现，如下：

```C
.macro PUSH_AND_CLEAR_REGS rdx=%rdx rax=%rax save_ret=0
    .if \save_ret
    pushq    %rsi        /* pt_regs->si */
    movq    8(%rsp), %rsi    /* temporarily store the return address in %rsi */
    movq    %rdi, 8(%rsp)    /* pt_regs->di (overwriting original return address) */
    .else
    pushq   %rdi        /* pt_regs->di */
    pushq   %rsi        /* pt_regs->si */
    .endif
    pushq    \rdx        /* pt_regs->dx */
    pushq   %rcx        /* pt_regs->cx */
    pushq   \rax        /* pt_regs->ax */
    pushq   %r8        /* pt_regs->r8 */
    pushq   %r9        /* pt_regs->r9 */
    pushq   %r10        /* pt_regs->r10 */
    pushq   %r11        /* pt_regs->r11 */
    pushq    %rbx        /* pt_regs->rbx */
    pushq    %rbp        /* pt_regs->rbp */
    pushq    %r12        /* pt_regs->r12 */
    pushq    %r13        /* pt_regs->r13 */
    pushq    %r14        /* pt_regs->r14 */
    pushq    %r15        /* pt_regs->r15 */
    UNWIND_HINT_REGS

    .if \save_ret
    pushq    %rsi        /* return address on top of stack */
    .endif

    xorl    %edx,  %edx    /* nospec dx  */
    xorl    %ecx,  %ecx    /* nospec cx  */
    xorl    %r8d,  %r8d    /* nospec r8  */
    xorl    %r9d,  %r9d    /* nospec r9  */
    xorl    %r10d, %r10d    /* nospec r10 */
    xorl    %r11d, %r11d    /* nospec r11 */
    xorl    %ebx,  %ebx    /* nospec rbx */
    xorl    %ebp,  %ebp    /* nospec rbp */
    xorl    %r12d, %r12d    /* nospec r12 */
    xorl    %r13d, %r13d    /* nospec r13 */
    xorl    %r14d, %r14d    /* nospec r14 */
    xorl    %r15d, %r15d    /* nospec r15 */

.endm
```

在执行`PUSH_AND_CLEAR_REGS`后，栈的情如下：

```text
     +------------+
+160 | %SS        |
+152 | %RSP       |
+144 | %RFLAGS    |
+136 | %CS        |
+128 | %RIP       |
+120 | ERROR CODE |
     |------------|
+112 | %RDI       |
+104 | %RSI       |
 +96 | %RDX       |
 +88 | %RCX       |
 +80 | %RAX       |
 +72 | %R8        |
 +64 | %R9        |
 +56 | %R10       |
 +48 | %R11       |
 +40 | %RBX       |
 +32 | %RBP       |
 +24 | %R12       |
 +16 | %R13       |
  +8 | %R14       |
  +0 | %R15       | <- %RSP
     +------------+
```

#### 3.1.2 按需切换内核栈

在保存通用寄存器后，我们再次检查是否来自用户空间，如下：

```C
    testb    $3, CS+8(%rsp)
    jz    .Lerror_kernelspace
```

根据截断的`RIP`寄存器值，可能会存在潜在的错误。无论如何，在两种情况下，都会调用[SWAPGS](https://www.felixcloutier.com/x86/swapgs)指令，交换`MSR_GS_BASE`和`MSR_KERNEL_GS_BASE`的值。此时，`%gs`寄存器将指向内核结构的基址。在此之后，调用`SWITCH_TO_KERNEL_CR3`宏切换到内核`cr3`，即，页表基址由用户页表切换到内核页表。整个过程如下：

```C
    SWAPGS
    FENCE_SWAPGS_USER_ENTRY
    /* We have user CR3.  Change to kernel CR3. */
    SWITCH_TO_KERNEL_CR3 scratch_reg=%rax
```

#### 3.1.3 同步寄存器值

在执行`SWAPGS`指令后，在从用户空间切换到内核空间时，跳转到`Lerror_entry_from_usermode_after_swapgs`标签继续执行，如下：

```C
.Lerror_entry_from_usermode_after_swapgs:
    /* Put us onto the real thread stack. */
    popq    %r12                /* save return addr in %12 */
    movq    %rsp, %rdi            /* arg0 = pt_regs pointer */
    call    sync_regs
    movq    %rax, %rsp            /* switch stack */
    ENCODE_FRAME_POINTER
    pushq    %r12
    ret
```

我们将栈指针的基址放到`%rdi`寄存器中，作为`sync_regs`函数调用的第一个参数，`sync_regs`函数在[arch/x86/kernel/traps.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/traps.c#L622)中定义，如下：

```C
asmlinkage __visible notrace struct pt_regs *sync_regs(struct pt_regs *eregs)
{
    struct pt_regs *regs = (struct pt_regs *)this_cpu_read(cpu_current_top_of_stack) - 1;
    if (regs != eregs)
        *regs = *eregs;
    return regs;
}
```

这个函数获取当前CPU的栈指针，并保存为当前的栈指针。`cpu_current_top_of_stack`宏在[arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/processor.h#L384)中定义，获取`cpu_tss_rw.x86_tss.sp1`的地址，表示正常内核栈的指针。如下

```C
#define cpu_current_top_of_stack cpu_tss_rw.x86_tss.sp1
```

因为，我们来着用户空间，这意味着异常处理程序将在真实的上下文中运行，将`sync_regs`返回的栈空间地址作为实际运行的栈空间地址。

### 3.2 必要时保存`cr2`寄存器值

检查`read_cr2`参数，需要保存时，将`cr2`寄存器中值保存到`%r12`寄存器中，在下面执行`do_sym`时作为第三个参数传递给中断处理函数，如下：

```C
    .if \read_cr2
    GET_CR2_INTO(%r12);
    .endif
```

`cr2`寄存器存放异常页的地址，通常在页异常时使用。

### 3.3 停止`IRQ`追踪

检查`shift_ist`，不等于`-1`时调用`TRACE_IRQS_OFF_DEBUG`；否则调用`TRACE_IRQS_OFF`；`TRACE_IRQS_OFF_DEBUG`对`TRACE_IRQS_OFF`进行了封装。如下：

```C
    .if \shift_ist != -1
    TRACE_IRQS_OFF_DEBUG            /* reload IDT in case of recursion */
    .else
    TRACE_IRQS_OFF
    .endif
```

### 3.4 保存寄存器值

#### 3.4.1 用户空间下切换

首先，检查`paranoid`标记，当处于用户空间时，调用`CALL_enter_from_user_mode`宏（最终调用`enter_from_user_mode`函数），如下：

```C
    .if \paranoid == 0
    testb    $3, CS(%rsp)
    jz    .Lfrom_kernel_no_context_tracking_\@
    CALL_enter_from_user_mode
.Lfrom_kernel_no_context_tracking_\@:
    .endif
```

`enter_from_user_mode`函数在[arch/arm64/kernel/traps.c](https://github.com/torvalds/linux/blob/v5.4/arch/arm64/kernel/traps.c#L906)中实现，如下：

```C
asmlinkage void enter_from_user_mode(void)
{
    CT_WARN_ON(ct_state() != CONTEXT_USER);
    user_exit_irqoff();
}
```

`enter_from_user_mode`函数检查当前运行上下文模式，在处于用户空间时（即，`CONTEXT_USER`），退出用户空间追踪统计信息。

#### 3.4.2 保存中断错误码

在此之后，保存`pt_regs`到`%rdi`；中断错误码到`%rsi`，无错误码时，保存`-1`，如下：

```C
    movq    %rsp, %rdi            /* pt_regs pointer */

    .if \has_error_code
    movq    ORIG_RAX(%rsp), %rsi        /* get error code */
    movq    $-1, ORIG_RAX(%rsp)        /* no syscall to restart */
    .else
    xorl    %esi, %esi            /* no error code */
    .endif
```

#### 3.4.3 必要时增加`TSS`栈空间

在`shift_ist ！= -1`的情况下，调用`CPU_TSS_IST`宏增加`TSS`栈空间，如下：

```C
    .if \shift_ist != -1
    subq    $\ist_offset, CPU_TSS_IST(\shift_ist)
    .endif
```

`CPU_TSS_IST`宏在同一个文件中定义，如下：

```C
#define CPU_TSS_IST(x) PER_CPU_VAR(cpu_tss_rw) + (TSS_ist + (x) * 8)
```

即，每次减少percpu变量上的`cpu_tss_rw`值来增加栈空间。用来处理在`#DB`中断处理过程中存在递归调用的情况下。

#### 3.4.4 必要时传递`cr2`参数

在需要读取`read_cr2`时，将`cr2`寄存器移动到第三个参数，如下：

```C
    .if \read_cr2
    movq    %r12, %rdx            /* Move CR2 into 3rd argument */
    .endif
```

### 3.5 执行中断函数

调用`do_sym`函数，执行实际的中断处理。如下：

```C
    call    \do_sym
```

即，`#DB`(调试)的中断处理执行`do_debug`函数，如下：

```C
dotraplinkage void do_debug(struct pt_regs *regs, long error_code);
```

### 3.6 退出中断处理

#### 3.6.1 必要时恢复`TSS`栈空间

在`shift_ist ！= -1`的情况下，调用`CPU_TSS_IST`宏恢复`TSS`栈空间，如下：

```C
    .if \shift_ist != -1
    addq    $\ist_offset, CPU_TSS_IST(\shift_ist)
    .endif
```

#### 3.6.2 中断退出

根据`paranoid`参数，通过`paranoid_exit`或`error_exit`恢复之前栈空间后退出。如下：

```C
    .if \shift_ist != -1
    addq    $\ist_offset, CPU_TSS_IST(\shift_ist)
    .endif

    .if \paranoid
    /* this procedure expect "no swapgs" flag in ebx */
    jmp    paranoid_exit
    .else
    jmp    error_exit
    .endif
```

`error_exit`宏在同一个文件中定义，如下：

```C
ENTRY(error_exit)
    UNWIND_HINT_REGS
    DISABLE_INTERRUPTS(CLBR_ANY)
    TRACE_IRQS_OFF
    testb    $3, CS(%rsp)
    jz    retint_kernel
    jmp    retint_user
END(error_exit)
```

首先，调用`DISABLE_INTERRUPTS`宏禁用所有的中断，`DISABLE_INTERRUPTS`展开后为`cli`指令；调用`TRACE_IRQS_OFF`停止`IRQ`追踪；最后，判断当前状态，处于用户空间时，调用`retint_user`，处于内核空间时，调用`retint_kernel`。

#### 3.6.3 返回到内核空间

`retint_kernel`宏在同一个文件中定义，在中断处理后，返回到内核空间，如下：

```C
retint_kernel:
#ifdef CONFIG_PREEMPTION
...
#endif
...
    TRACE_IRQS_IRETQ

GLOBAL(restore_regs_and_return_to_kernel)
#ifdef CONFIG_DEBUG_ENTRY
...
#endif
    POP_REGS
    addq    $8, %rsp    /* skip regs->orig_ax */
...
    INTERRUPT_RETURN
```

首先，在`CONFIG_PREEMPTION`内核配置选项开启的情况下，处理抢占；之后，调用`TRACE_IRQS_IRETQ`宏，启用`IRQ`中断；调用`POP_REGS`宏恢复通用寄存器；最终，调用`INTERRUPT_RETURN`执行`iret`指令返回。

#### 3.6.4 返回到用户空间

`retint_user`宏在同一个文件中定义，在中断处理后，返回到用户空间，如下：

```C
GLOBAL(retint_user)
mov %rsp,%rdi
    call    prepare_exit_to_usermode
...
```

##### 3.6.4.1 返回到用户空间的准备

首先，调用`prepare_exit_to_usermode`函数处理退回到用户空间的准备，`prepare_exit_to_usermode`函数在[arch/x86/entry/common.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/common.c#L181)中定义实现。

##### 3.6.4.2 启用IRQ中断

之后，调用`TRACE_IRQS_IRETQ`宏启用`IRQ`中断。

##### 3.6.4.3 恢复通用寄存器

调用`POP_REGS pop_rdi=0`恢复保存的通用寄存器状态。

##### 3.6.4.4 恢复`trampoline`栈

在内核空间下，需要通过`trampoline`栈跳转到用户空间，现在构建跳转用的`trampoline`栈。如下：

```C
    movq    %rsp, %rdi
    movq    PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
    UNWIND_HINT_EMPTY

    /* Copy the IRET frame to the trampoline stack. */
    pushq    6*8(%rdi)    /* SS */
    pushq    5*8(%rdi)    /* RSP */
    pushq    4*8(%rdi)    /* EFLAGS */
    pushq    3*8(%rdi)    /* CS */
    pushq    2*8(%rdi)    /* RIP */

    /* Push user RDI on the trampoline stack. */
    pushq    (%rdi)
```

##### 3.6.4.5 切换到用户栈

最后，我们调用`SWITCH_TO_USER_CR3_STACK`宏设置用户空间页表基址；调用`SWAPGS`交换栈空间，此时，`%gs`指向用户栈基址；最后，调用`INTERRUPT_RETURN`跳转返回。

```C
    SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi

    /* Restore RDI. */
    popq    %rdi
    SWAPGS
    INTERRUPT_RETURN
```

## 4 内核空间的中断处理过程（`idtentry_part`宏）

在上面的过程中，我们分析了在用户模式下中断的处理过程。在分析的过程中，我们只处理`paranoid=0`的情况，即，执行`error_entry`和`error_exit`。接下来，我们继续分析在内核模式下，`paranoid=1`时中断处理过程，即，执行`paranoid_entry`和`paranoid_exit`。`paranoid`意味着，我们需要使用一种更慢的方式来检查是否真正处于内核空间。

### 4.1 中断处理前的准备（`paranoid_entry`）

`paranoid_entry`宏在同一个文件中定义，如下：

```C
ENTRY(paranoid_entry)
    UNWIND_HINT_FUNC
    cld
    PUSH_AND_CLEAR_REGS save_ret=1
    ENCODE_FRAME_POINTER 8
    movl    $1, %ebx
    movl    $MSR_GS_BASE, %ecx
    rdmsr
    testl    %edx, %edx
    js    1f                /* negative -> in kernel */
    SWAPGS
    xorl    %ebx, %ebx

1:
...
    SAVE_AND_SWITCH_TO_KERNEL_CR3 scratch_reg=%rax save_reg=%r14
    FENCE_SWAPGS_KERNEL_ENTRY
    ret
END(paranoid_entry)
```

首先，调用`PUSH_AND_CLEAR_REGS`保存通用寄存器后；通过`rdmsr`方式来判断是否真正处于内核模式；之后，调用`SAVE_AND_SWITCH_TO_KERNEL_CR3`切换到内核页表后返回。这种方式的区别在于是否执行`SWAPGS`指令，即，交互切换`%gs`寄存器值。

之后的中断处理同用户空间下处理过程相同。

### 4.2 中断处理退出（`paranoid_exit`）

在中断处理完成后，执行`paranoid_exit`退出中断处理。如下

```C
ENTRY(paranoid_exit)
    UNWIND_HINT_REGS
    DISABLE_INTERRUPTS(CLBR_ANY)
    TRACE_IRQS_OFF_DEBUG
    testl    %ebx, %ebx            /* swapgs needed? */
    jnz    .Lparanoid_exit_no_swapgs
    TRACE_IRQS_IRETQ
    /* Always restore stashed CR3 value (see paranoid_entry) */
    RESTORE_CR3    scratch_reg=%rbx save_reg=%r14
    SWAPGS_UNSAFE_STACK
    jmp    .Lparanoid_exit_restore
.Lparanoid_exit_no_swapgs:
    TRACE_IRQS_IRETQ_DEBUG
    /* Always restore stashed CR3 value (see paranoid_entry) */
    RESTORE_CR3    scratch_reg=%rbx save_reg=%r14
.Lparanoid_exit_restore:
    jmp restore_regs_and_return_to_kernel
END(paranoid_exit)
```

在调用`DISABLE_INTERRUPTS`禁用中断后，执行`TRACE_IRQS_OFF_DEBUG`停止`IRQ`追踪；在判断是否交换`swapgs`后进行对应操作，调用`TRACE_IRQS_IRETQ`或`TRACE_IRQS_IRETQ_DEBUG`开启`IRQ`中断，恢复`cr3`寄存器值；需要交换时，执行`SWAPGS_UNSAFE_STACK`交换`%gs`；最终，调用`restore_regs_and_return_to_kernel`返回到内核空间。

以上，就是整个中断处理过程。

## 5 结束语

在前面的部分，我们描述了IDT及门的设置过程，在`setup_arch`中，我们设置了`#DB`和`#BP`门。本文开始深入分析中断前的准备、中断处理、中断退出的整个处理过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
