# 中断和中断处理 （第一部分）

## 0 介绍

我们已经在初始化过程中听到过很多次`中断（interrupts）`这个词，也看到过几个关于中断的例子。在这一章中我们将会从下面的主题开始：

* 什么是`中断（interrupts）` ？
* 什么是`中断处理（interrupt handlers）` ？

我们将会继续深入探讨`中断`的细节和Linux内核如何处理这些中断。

看到中断首先想到的第一个问题是什么是`中断`？中断就是当软件或者硬件需要使用`CPU`时引发的`事件（event）`。比如，当我们在键盘上按下一个键的时候，我们下一步期望做什么？操作系统和电脑应该怎么做？做一个简单的假设，每一个物理硬件都有一根连接CPU的中断线，设备可以通过它对CPU发起中断信号。但是中断信号并不是直接发送给CPU。在老式单处理器的机器上中断信号发送给[PIC，Programmable interrupt controller](http://en.wikipedia.org/wiki/Programmable_Interrupt_Controller)，它是一个顺序处理各种设备的各种中断请求的芯片。在SMP多处理器机器上，则是通过[高级程序中断控制器（APIC，Advanced Programmable Interrupt Controller）](https://en.wikipedia.org/wiki/Advanced_Programmable_Interrupt_Controller)来负责处理中断。

一个`APIC`包括两个独立的设备，`本地APIC(Local APIC)`和`I/O APIC`。第一个设备 - 本地APIC存在于每个CPU核心中，负责处理特定于CPU的中断配置。本地APIC常被用于管理来自 APIC时钟（APIC-timer）、热敏元件和其他与I/O设备连接的设备的中断。第二个设备 - `I/O APIC`提供了多核处理器的中断管理，所有本地APIC都连接到一个外部的I/O APIC。

## 1 中断向量

正如你理解的那样，中断可以在任何时间触发。当一个中断触发时，操作系统必须立刻处理它。但是`处理一个中断`是什么意思呢？当一个中断触发时，操作系统必须确保下面的步骤顺序：

* 内核必须暂停执行当前进程(取代当前的任务)；
* 内核必须搜索中断处理程序并且转交控制权(执行中断处理程序)；
* 中断处理程序结束之后，被中断的进程能够恢复执行。

当然，在这个中断处理程序中会涉及到很多错综复杂的过程，但是上面3条是中断处理程序的基本骨架。

每个中断处理程序的地址都保存在一个特殊的位置，这个位置被称为`中断描述符表（IDT, Interrupt Descriptor Table）`。处理器使用唯一的数字来标识中断和异常的类型，这个数字被称为`中断向量（vector number）`。一个中断向量对应一个`IDT`的标识，中断向量范围是有限的，是从`0`到`255`之间的数字。你可以在Linux 内核源码中找到下面的中断向量范围检查代码：

```C
BUG_ON((unsigned)n > 0xFF);
```

你可以在Linux内核源码中关于中断设置的地方找到这个检查(例如：[arch/x86/kernel/idt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/idt.c#L230)中的`set_intr_gate`函数）。从`0`到`31`的前`32`个中断向量被处理器保留，用于处理架构定义的异常和中断。你可以在 Linux内核初始化第二部分 - 早期中断和异常处理中找到这个表和关于这些中断标识码的描述。从`32`到`255`的中断向量设计为用户定义中断并且不被系统保留。这些中断通常分配给外部 I/O设备，使这些设备可以发送中断给处理器。

`0 ~ 31`号中断向量如下：

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

## 2 中断的分类

现在，我们来讨论中断的类型。笼统地来讲，我们可以把中断分为两个主要类型，中断和异常。

**中断**
由本地APIC或者与本地APIC连接的处理器针脚接收的外部硬件中断。可分为

* 可屏蔽中断（maskable interrupt）
  I/O设备发出的所有中断请求（IRQ）都产生可屏蔽中断。可屏蔽中断可以处于两种状态：屏蔽的（masked）或非屏蔽的（unmasked），一个屏蔽的中断只要还是处于屏蔽状态，控制单元就忽略它.
* 非屏蔽中断（nomaskable interrupt）
  只有几个危急事件（如硬件故障）才引起非屏蔽中断。非屏蔽中断总是由CPU辨认。

**异常**
由CPU检测到的异常指令或由用户触发引起的软件中断。

* 处理探测异常（processor-detected exception）
  当CPU执行指令时探测到的一个反常条件所产生的异常。根据`eip`寄存器的值可以进一步可以分为三种情况：
  * 故障（fault）- 执行的是一个“不完善的”指令，通常可以纠正，一旦纠正，程序就可以在不失连贯性的情况下重新开始。此时，`eip`中的值是引起故障的指令地址。在异常程序终止时，那条指令会被重新执行。如处理缺页等。
  * 缺陷（trap）- 在缺陷指令执行后立即报告，内核把控制权返回给程序后就可以继续它的执行而保持连贯性。`eip`中的值是一个随后要执行的地址。缺陷主要用于调试程序。
  * 异常终止（abort） - 发生了一个严重的错误，控制单元出现了错误，不能在`eip`保存异常指令的确切位置。用于报告严重的错误，如硬件故障或系统表中无效的值或不一致的值等。由控制单元发的，用来把控制权切换到相应的异常终止处理程序。
* 编程异常（programmed exception）
  在编程者发出请求发生。由`int`或`int3`指令触发的。控制单元把编程异常当做缺陷来处理。编程异常通常也叫做软中断（soft interrupt）。

我们已经从前面的部分知道，中断可以分为`可屏蔽的（maskable）`和`不可屏蔽的（non-maskable）`。可屏蔽的中断可以被忽略的，在`x86_64`下使用`sti`和`cli`指令来禁用和启用中断。在Linux内核代码中通过`native_irq_disable`和`native_irq_enable`函数实现：

```C
static inline void native_irq_disable(void)
{
        asm volatile("cli": : :"memory");
}

static inline void native_irq_enable(void)
{
        asm volatile("sti": : :"memory");
}
```

这两个指令修改了在中断寄存器中的`IF`标识位，`sti`指令设置`IF`标识，`cli`指令清除这个标识。不可屏蔽中断总是被处理，通常，任何硬件上的失败都映射为不可屏蔽中断。

如果同时发生多个异常或者中断，处理器按照事先设定的中断优先级来处理他们。中断优先级从低到高的顺序如下：

```text
+----------------------------------------------------------------+
|   Priority   | Description                                     |
+--------------+-------------------------------------------------+
|              | Hardware Reset and Machine Checks               |
|     1        | - RESET                                         |
|              | - Machine Check                                 |
+--------------+-------------------------------------------------+
|              | Trap on Task Switch                             |
|     2        | - T flag in TSS is set                          |
+--------------+-------------------------------------------------+
|              | External Hardware Interventions                 |
|              | - FLUSH                                         |
|     3        | - STOPCLK                                       |
|              | - SMI                                           |
|              | - INIT                                          |
+--------------+-------------------------------------------------+
|              | Traps on the Previous Instruction               |
|     4        | - Breakpoints                                   |
|              | - Debug Trap Exceptions                         |
+--------------+-------------------------------------------------+
|     5        | Nonmaskable Interrupts                          |
+--------------+-------------------------------------------------+
|     6        | Maskable Hardware Interrupts                    |
+--------------+-------------------------------------------------+
|     7        | Code Breakpoint Fault                           |
+--------------+-------------------------------------------------+
|     8        | Faults from Fetching Next Instruction           |
|              | Code-Segment Limit Violation                    |
|              | Code Page Fault                                 |
+--------------+-------------------------------------------------+
|              | Faults from Decoding the Next Instruction       |
|              | Instruction length > 15 bytes                   |
|     9        | Invalid Opcode                                  |
|              | Coprocessor Not Available                       |
+--------------+-------------------------------------------------+
|     10       | Faults on Executing an Instruction              |
|              | Overflow                                        |
|              | Bound error                                     |
|              | Invalid TSS                                     |
|              | Segment Not Present                             |
|              | Stack fault                                     |
|              | General Protection                              |
|              | Data Page Fault                                 |
|              | Alignment Check                                 |
|              | x87 FPU Floating-point exception                |
|              | SIMD floating-point exception                   |
|              | Virtualization exception                        |
+--------------+-------------------------------------------------+
```

## 3 中断实现过程

### 3.1 中断描述符表（IDT）介绍

现在我们已经了解了一些关于关于中断和异常的内容，现在我们来看下其实现过程。我们从`中断描述符表（IDT，Interrupt Descriptor Table）`开始。`IDT`类似于`全局描述符表（GDT，Global Descriptor Table）`结构，它保存了中断和异常处理程序的入口地址。与`GDT`不同的是，`IDT`中的项被称为`门（gates）`，而不是`描述符（descriptors）`。`IDT`按照类型分为：

* 中断门（Interrupt gates）
* 任务门（Task gates）
* 陷阱门（Trap gates）
  
在`x86`架构中，只有在`x86_64`的[长模式（long mode）](https://en.wikipedia.org/wiki/Long_mode)下，中断门和陷阱门才可以引用。`IDT`在`x86`下是一个`8`字节数组，而在`x86_64`上是一个`16`字节数组。`IDT`的第一个元素可以是一个门，但它并不是强制要求的。比如，我们在切换到[保护模式（protected mode）](http://en.wikipedia.org/wiki/Protected_mode)时用`NULL`门加载过中断描述符表，在[arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/pm.c#L93) 实现，如下：

```C
/*
 * Set up the IDT
 */
static void setup_idt(void)
{
    static const struct gdt_ptr null_idt = {0, 0};
    asm volatile("lidtl %0" : : "m" (null_idt));
}
```

`IDT`可以指向任意的线性地址空间和基地址，只要在`x86`上以`8`字节对齐，在`x86_64`上以`16`字节对齐。`IDT`的基址存储在一个叫做`IDTR`的特殊寄存器中，在`x86`上通过`LIDT`和`SIDT`两个指令协调工作来修改`IDTR`寄存器。`LIDT`指令用来加载`IDT`的基址，即在`IDTR`的指定操作数。`SIDT`用来在指定操作数中读取和存储`IDTR`的内容。在`x86`上`IDTR`寄存器是`48`位，包含了下面的信息：

```text
+-----------------------------------+----------------------+
|                                   |                      |
|     Base address of the IDT       |   Limit of the IDT   |
|                                   |                      |
+-----------------------------------+----------------------+
47                                16 15                    0
```

让我们看看`setup_idt`的实现，我们准备了一个`null_idt`，使用`lidt`指令把它加载到`IDTR`寄存器中。其中，`null_idt`是`gdt_ptr`类型，后者定义如下：

```C
struct gdt_ptr {
        u16 len;
        u32 ptr;
} __attribute__((packed));
```

正如示意图中看到的一样，`IDTR`结构由`2`字节和`4`字节（共`48`位）的两个域组成。接下来，让我们看看`IDT`目录项结构，在`x86_64`架构下是一个`16`字节的结构，通常叫做`门(gate)`。结构如下：

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

`IST（Interrupt Stack Table)`是`x86_64`中提供的栈切换新机制，它用来代替传统的栈切换机制。之前的`x86`架构中提供了一种在响应中断时自动切换栈帧的机制。`IST`是`x86`栈切换模式的一个修改版，在它启用后可以无条件地切换栈，并且可以从任何与`IDT`关联条目的特定中断中启用。从这里可以看出，并不是所有的中断都需要`IST`，一些中断可以继续使用传统的栈切换模式。`IST`机制在[任务状态段（TSS, Task State Segment）](https://en.wikipedia.org/wiki/Task_state_segment)中提供了`7`个`IST`指针。`TSS`是一个包含进程信息的特殊结构，用来在执行中断或者处理Linux内核异常的时候进行栈切换。每一个指针都被`IDT`中的中断门引用。

`中断描述符表(IDT)`使用`gate_desc`的数组来描述，在[arch/x86/include/asm/desc_defs.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/desc_defs.h#L88)定义，如下：

```C
extern gate_desc idt_table[];
...
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

### 3.2 中断栈（irq_stack）介绍

在`x86_64`架构中，每一个活动的线程在Linux内核中都有一个初始的栈。这个栈的大小由`THREAD_SIZE`定义，`THREAD_SIZE`在[arch/x86/include/asm/page_64_types.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page_64_types.h#L15)中定义，如下：

```C
#define PAGE_SHIFT      12
#define PAGE_SIZE       (_AC(1,UL) << PAGE_SHIFT)
...
#ifdef CONFIG_KASAN
#define KASAN_STACK_ORDER 1
#else
#define KASAN_STACK_ORDER 0
#endif

#define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
```

`PAGE_SIZE`是4096字节，`THREAD_SIZE_ORDER`的值依赖于`KASAN_STACK_ORDER`，而`KASAN_STACK_ORDER`依赖于 `CONFIG_KASAN`内核配置选项。

`KASAN`是一个运行时内存调试器，如果`CONFIG_KASAN`被禁用，`THREAD_SIZE`是`16K`；如果内核配置选项打开，`THREAD_SIZE`的值是`32K`。这块栈空间在线程处于活动状态或僵尸状态时保存着有用的数据，但是当线程处于用户空间时，这个内核栈是空的。每个可用的CPU关联着一些特殊的栈空间，当CPU上执行内核代码的时候，这些栈处于活动状态；当CPU执行用户空间代码时，这些栈不包含任何有用的信息。每个CPU都拥有一些per-cpu栈，第一个就是给外部中断使用的`中断栈（interrupt stack）`。它的大小由`IRQ_STACK_SIZE`定义，在[arch/x86/include/asm/page_64_types.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page_64_types.h#L22)定义，如下：

```C
#define IRQ_STACK_ORDER (2 + KASAN_STACK_ORDER)
#define IRQ_STACK_SIZE (PAGE_SIZE << IRQ_STACK_ORDER)
```

`IRQ_STACK_SIZE`同样依赖于`CONFIG_KASAN`的内核配置选项，其大小为`16K`或`32K`。per-cpu的中断栈使用`irq_stack`和`fixed_percpu_data`结构来描述，在[arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/processor.h#L374)中定义，如下：

```C
/* Per CPU interrupt stacks */
struct irq_stack {
	char		stack[IRQ_STACK_SIZE];
} __aligned(IRQ_STACK_SIZE);

...

#ifdef CONFIG_X86_64
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

`irq_stack`结构包含一个`16KB`的数组，`fixed_percpu_data`这个结构体有两个字段：

* `gs_base` - `gs`寄存器总是指向`fixed_percpu_data`的底部。在`x86_64`中，per-cpu区域和`stack canary`共享`gs`寄存器。所有的per-cpu符号都是从零开始的，并且`gs`指向per-cpu区域的开始位置。[段内存模型](http://en.wikipedia.org/wiki/Memory_segmentation)在长模式下已经废除很久了，但是我们可以使用[特殊模块寄存器（Model specific registers）](https://en.wikipedia.org/wiki/Model-specific_register)给这`fs`和`gs`两个段寄存器设置基址，并且这些寄存器仍然可以被用作地址寄存器。如果你记得Linux内核初始程序的第一部分，你会记起我们设置了`gs`寄存器：

```C
    movl    $MSR_GS_BASE,%ecx
    movl    initial_gs(%rip),%eax
    movl    initial_gs+4(%rip),%edx
    wrmsr
```

`initial_gs`指向`fixed_percpu_data`，如下：

```C
	GLOBAL(initial_gs)
	.quad	INIT_PER_CPU_VAR(fixed_percpu_data)
```

* `stack_canary` - [Stack canary](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries)用来验证栈是否已经被修改的栈保护者（stack protector）。`gs_base`是一个`40`字节的数组，GCC要求`stack canary`在离`gs`开始有固定的偏移量，这个偏移量在`x86_64`架构上必须是40，在`x86`架构上必须是20。

`fixed_percpu_data`是percpu的第一个数据, 我们可以在`System.map`中看到定义：

```C
0000000000000000 D __per_cpu_start
0000000000000000 D fixed_percpu_data
00000000000001e0 A kexec_control_code_size
0000000000001000 D cpu_debug_store
0000000000002000 D irq_stack_backing_store
0000000000006000 D cpu_tss_rw
0000000000009000 D gdt_page
000000000000a000 d exception_stacks
000000000000f000 d entry_stack_storage
...
```

在[arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/processor.h#L398)中找到`fixed_percpu_data`和其他percpu变量的定义：

```C
DECLARE_PER_CPU(struct irq_stack *, hardirq_stack_ptr);
...
DECLARE_PER_CPU(unsigned int, irq_count);
...
DECLARE_PER_CPU(struct irq_stack *, softirq_stack_ptr);
...
DECLARE_PER_CPU_FIRST(struct fixed_percpu_data, fixed_percpu_data) __visible;
DECLARE_INIT_PER_CPU(fixed_percpu_data);
...
```

`hardirq_stack_ptr`和`softirq_stack_ptr`指向硬件中断和软中断的栈指针，`irq_count`用来检查CPU是否处于中断栈。`hardirq_stack_ptr`在[arch/x86/kernel/irq_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/irq_64.c#L67)的`irq_init_percpu_irqstack`中初始化，如下：

```C
int irq_init_percpu_irqstack(unsigned int cpu)
{
	if (per_cpu(hardirq_stack_ptr, cpu))
		return 0;
	return map_irq_stack(cpu);
}
```

逐个检查所有CPU并设置`hardirq_stack_ptr`，调用`map_irq_stack`函数来初始化`hardirq_stack_ptr`，将`hardirq_stack_ptr`指向当前CPU`irq_stack_backing_store`后的`IRQ_STACK_SIZE`的偏移量。

在初始化完中断栈后，我们在[arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/common.c#L571)初始化`gs`寄存器。如下：

```C
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

现在我们可以看到`wrmsr`指令，这个指令从`edx:eax`加载数据到`ecx`指向的[MSR寄存器](https://en.wikipedia.org/wiki/Model-specific_register)。在这里MSR寄存器是`MSR_GS_BASE`，它保存了`gs`寄存器指向的内存段的基址。`edx:eax`指向`initial_gs`的地址，即`fixed_percpu_data`的基址。

### 3.3 中断栈表（IST）切换过程

在前面描述中，我们知道在`x86_64`下通过一个特殊的栈（即，`中断栈表（IST，Interrupt Stack Table）`），在发生不可屏蔽中断、双重错误等的时候，提供了切换到新栈的功能。在per-cpu中最多可以有7个`IST`项，其中一些[arch/x86/include/asm/page_64_types.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/page_64_types.h#L27)定义如下:

```C
/*
 * The index for the tss.ist[] array. The hardware limit is 7 entries.
 */
#define	IST_INDEX_DF		0
#define	IST_INDEX_NMI		1
#define	IST_INDEX_DB		2
#define	IST_INDEX_MCE		3
```

所有被`IST`切换到新栈的中断门描述符都由`idt_setup_from_table`函数初始化。`idt_setup_from_table`函数初始化`struct idt_data def_idts[]`数组中的每个门描述符，在[arch/x86/kernel/idt.c](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/idt.c#L79)定义，如下:

```C
static const __initconst struct idt_data def_idts[] = {
    ...
	INTG(X86_TRAP_NMI,		nmi),
    ...
	INTG(X86_TRAP_DF,		double_fault),
    ...
```

其中`nmi`和`double_fault`是中断函数的入口地址，在[arch/x86/include/asm/traps.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/traps.h#L15)中声明，如下：

```C
asmlinkage void nmi(void);
asmlinkage void double_fault(void);
```

在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L1030)中定义，如下：

```C
idtentry double_fault			do_double_fault			has_error_code=1 paranoid=2 read_cr2=1
...
ENTRY(nmi)
...
...
...
END(nmi)
```

当一个中断或者异常发生时，新的`ss`选择器被强制置为NULL，并且`ss`选择器的`rpl`字段设置为新的`cpl`。旧的`ss`、`rsp`、寄存器标志、`cs`、`rip`被压入新栈。在`64`位下，中断栈帧大小固定为`8`字节，所以我们可以得到下面的栈:

```C
+---------------+
|               |
|      SS       | 40
|      RSP      | 32
|     RFLAGS    | 24
|      CS       | 16
|      RIP      | 8
|   Error code  | 0
|               |
+---------------+
```

如果在中断门中`IST`字段不是0，我们把`IST`读到`rsp`中。如果它关联了一个中断向量错误码，我们再把这个错误码压入栈。如果中断向量没有错误码，就继续并且把虚拟错误码压入栈。我们必须按照上述的步骤来确保栈一致性。接下来我们从门描述符中加载段选择器域到`CS`寄存器中，并且通过验证第`21`位的值来验证目标代码是一个`64`位代码段，即：全局描述符表（Global Descriptor Table）中的`L`位。最后我们从门描述符中加载偏移量到`rip`中，`rip`是中断处理函数的入口地址。然后中断函数开始执行，在中断函数执行结束后，它必须通过`iret`指令把控制权交还给被中断进程。`iret`指令无条件地弹出栈指针`（ss:rsp）`来恢复被中断的进程，并且不会依赖于`cpl`改变。

## 4 结束语

本文描述了Linux内核的中断和中断处理的第一部分，我们初步了解了一些中断、异常相关的理论基础。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
