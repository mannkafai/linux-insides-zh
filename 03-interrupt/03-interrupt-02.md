# 中断和中断处理 （第二部分）

## 0 深入Linux内核中的中断和异常处理

在上一章节中我们学习了中断和异常处理的一些理论知识，在本章节中，我们将深入了解Linux内核源代码中关于中断与异常处理的部分。像其他章节一样，我们将从启动早期的代码开始阅读。从本章开始从中断与异常处理相关的最早期代码开始阅读，了解Linux内核源代码中所有与中断和异常处理相关的代码。

## 1 实模式下中断设置

在前面Linux内核初始化的部分，Linux内核中`x86_64`架构关于中断相关的最早代码出现在[arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/pm.c#L93)文件中，在该文件中首次设置了[中断描述符表(IDT)](https://en.wikipedia.org/wiki/Interrupt_descriptor_table)。在调用`go_to_protected_mode`函数将处理器切换到保护模式前，该函数调用`setup_idt`函数配置IDT，如下：

```C
void go_to_protected_mode(void)
{
        ...
        setup_idt();
        ...
}
```

`setup_idt`函数在同一文件中定义，它仅仅是用 NULL填充了中断描述符表:

```C
static void setup_idt(void)
{
        static const struct gdt_ptr null_idt = {0, 0};
        asm volatile("lidtl %0" : : "m" (null_idt));
}
```

其中，`gdt_ptr`结构描述了一个特殊的48-bit寄存器，即：`GDTR`，它描述了[全局描述符表(GDT)](https://en.wikipedia.org/wiki/Global_Descriptor_Table)的结构，如下:

```C
struct gdt_ptr {
        u16 len;
        u32 ptr;
} __attribute__((packed));
```

显然，此处的`gdt_prt`不是表示`GDTR`寄存器而是表示`IDTR`寄存器，因为我们将其设置到了中断描述符表中。在Linux内核代码中没有`idt_ptr`结构体，是因为它与`gdt_prt`具有相同的结构而仅仅是名字不同，因此没必要定义两个重复的数据结构。可以看到，内核在此处并没有填充IDT，是因为此刻处理任何中断或异常还为时尚早，因此我们仅仅以NULL来填充IDT。

在设置完IDT, GDT和其他一些东西以后，内核开始进入保护模式，这部分代码在[arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/pmjump.S)中实现，你可以在描述如何进入保护模式的章节中了解到更多细节。

## 2 平台相关内核初始化阶段设置

### 2.1 从保护模式到内核初始化的过程

进行保护模式的入口点位于`boot_params.hdr.code32_start`，在[arch/x86/boot/pm.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/pm.c#L122)的末尾看到内核将入口函数地址和启动参数`boot_params`传递给了`protected_mode_jump`函数:

```C
protected_mode_jump(boot_params.hdr.code32_start,
                            (u32)&boot_params + (ds() << 4));
```

`protected_mode_jump`函数在文件[arch/x86/boot/pmjump.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/pmjump.S)定义，通过[8086的调用约定](https://en.wikipedia.org/wiki/X86_calling_conventions#List_of_x86_calling_conventions)，通过`ax`和`dx`两个寄存器来传递参数:

```C
GLOBAL(protected_mode_jump)
        ...
        ...
        ...
        .byte   0x66, 0xea              # ljmpl opcode
2:      .long   in_pm32                 # offset
        .word   __BOOT_CS               # segment
...
...
...
ENDPROC(protected_mode_jump)
```

其中，`in_pm32`包含了对32-bit入口的跳转语句:

```C
GLOBAL(in_pm32)
        ...
        ...
        jmpl    *%eax            # Jump to the 32-bit entrypoint
ENDPROC(in_pm32)
```

你可能还记得32-bit的入口点位于汇编文件[arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/head_64.S#L48)中，尽管它的名字包含`_64`后缀。我们可以在`arch/x86/boot/compressed`目录下看到两个相似的文件，`arch/x86/boot/compressed/head_32.S`和`arch/x86/boot/compressed/head_64.S`。然而32-bit模式的入口位于第二个文件中，而第一个文件在`x86_64`配置下不会参与编译，在[arch/x86/boot/compressed/Makefile](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/Makefile#L75)中，可以找到生成目标：

```C
vmlinux-objs-y := $(obj)/vmlinux.lds $(obj)/head_$(BITS).o $(obj)/misc.o \
    $(obj)/string.o $(obj)/cmdline.o $(obj)/error.o \
    $(obj)/piggy.o $(obj)/cpuflags.o
```

生成目标中包括 `$(obj)/head_$(BITS).o` ，这意味着我们将会选择基于`$(BITS)`设置的文件执行链接操作，即`head_32.o`或者 `head_64.o`。`$(BITS)`在[arch/x86/Makefile](https://github.com/torvalds/linux/blob/v5.4/arch/x86/Makefile#L64)中定义的：

```bash
ifeq ($(CONFIG_X86_32),y)
        BITS := 32
        ...
else
        BITS := 64
        ...
endif
```

现在我们从[arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/head_64.S#L48)跳入了`startup_32`函数，在这个函数中没有与中断处理相关的内容。`startup_32`函数进行进入[长模式](http://en.wikipedia.org/wiki/Long_mode)前必须的准备工作后，直接切换到长模式。

长模式的入口点为`startup_64`函数，在这个函数中完成了内核解压的准备工作。内核解压的代码位于[arch/x86/boot/compressed/misc.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/misc.c#L340)中的`extract_kernel`函数中。内核解压完成以后，程序跳入[arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head_64.S#L53)中的`startup_64`函数。

### 2.2 中断栈介绍

在`startup_64`函数中，我们开始构建映射内存，检查[NX](http://en.wikipedia.org/wiki/NX_bit)位、设置`EFER(Extended Feature Enable Register)`寄存器、使用`lgdt`指令更新早期的GDT，在此之后我们设置`gs`寄存器，如下：

```C
    movl    $MSR_GS_BASE,%ecx
    movl    initial_gs(%rip),%eax
    movl    initial_gs+4(%rip),%edx
    wrmsr
```

这段代码在之前的章节中出现过。请注意代码最后的`wrmsr`指令，这个指令将`edx:eax`寄存器指定的地址中的数据写入到由`ecx`寄存器指定的[model specific register](https://en.wikipedia.org/wiki/Model-specific_register)中。由代码可以看到，`ecx`中的值是`$MSR_GS_BASE`，该值在[arch/x86/include/asm/msr-index.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/msr-index.h#L21)中定义，如下:

```C
#define MSR_GS_BASE             0xc0000101
```

由此可见，`MSR_GS_BASE`定义了`model specific register`的编号。由于`cs`, `ds`, `es`,和 `ss`在64-bit模式中不再使用，这些寄存器中的值将会被忽略，但我们可以通过 `fs`和 `gs`寄存器来访问内存空间。`model specific register`提供了来访问这些段寄存器的一种后门，让我们可以通过段寄存器 `fs`和 `gs`来访问64-bit的基地址。`MSR_GS_BASE`是个隐藏的部分，这部分代码映射在`GS.base`中。再看到 `initial_gs`函数的定义:

```C
    GLOBAL(initial_gs)
    .quad    INIT_PER_CPU_VAR(fixed_percpu_data)
```

这段代码将`fixed_percpu_data`传递给`INIT_PER_CPU_VAR`宏，后者只是给输入参数添加了`init_per_cpu__`前缀而已。在此得出了符号 `init_per_cpu__fixed_percpu_data`。再看到[链接脚本](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/vmlinux.lds.S#L436)，其中可以看到如下定义:

```C
#define INIT_PER_CPU(x) init_per_cpu__##x = ABSOLUTE(x) + __per_cpu_load
INIT_PER_CPU(fixed_percpu_data);
```

这段代码告诉我们符号`init_per_cpu__fixed_percpu_data`的地址将会是 `fixed_percpu_data` + `__per_cpu_load`。现在再来看看`init_per_cpu__fixed_percpu_data`和 `__per_cpu_load`在哪里。`fixed_percpu_data`的定义出现在[arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/processor.h#L399)中，其中的`DECLARE_INIT_PER_CPU`宏展开后又调用了`init_per_cpu_var`宏，如下：

```C
DECLARE_PER_CPU_FIRST(struct fixed_percpu_data, fixed_percpu_data) __visible;
DECLARE_INIT_PER_CPU(fixed_percpu_data);

#define DECLARE_INIT_PER_CPU(var) \
       extern typeof(var) init_per_cpu_var(var)

#ifdef CONFIG_X86_64_SMP
#define init_per_cpu_var(var)  init_per_cpu__##var
#else
#define init_per_cpu_var(var)  var
#endif
```

将所有的宏展开之后我们可以得到与之前相同的名称`init_per_cpu__fixed_percpu_data`，但此时它不再只是一个符号，而成了一个变量。请注意表达式`typeof(var)`,在此时`var`是 `fixed_percpu_data`，`PER_CPU_VAR`宏在[arch/x86/include/asm/percpu.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/percpu.h#L31)中定义:

```C
#define PER_CPU_VAR(var)        %__percpu_seg:var
...
#ifdef CONFIG_X86_64
    #define __percpu_seg gs
endif
```

因此，我们实际访问的是`gs:fixed_percpu_data`，它的类型是`fixed_percpu_data`。到此为止，我们定义了上面所说的第一个变量并且知道了它的地址。再看到第二个符号 `__per_cpu_load`，该符号定义在[include/asm-generic/sections.h](https://github.com/torvalds/linux/blob/v5.4/include/asm-generic/sections.h#L42)中定义，这个符号定义了一系列`per-cpu`变量，如下：

```C
extern char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];
```

这些符号代表了这一系列变量的数据区域的基地址。因此我们知道了`fixed_percpu_data`和`__per_cpu_load`的地址，并且知道变量`init_per_cpu__fixed_percpu_data`位于 `__per_cpu_load`后面，并且在[System.map](https://en.wikipedia.org/wiki/System.map)中可以看到：

```C
...
ffffffff82869000 D __init_begin
ffffffff82869000 D __per_cpu_load
ffffffff82869000 A init_per_cpu__fixed_percpu_data
...
```

现在我们终于知道了`initial_gs`表示什么，回到之前的代码中:

```C
movl    $MSR_GS_BASE,%ecx
movl    initial_gs(%rip),%eax
movl    initial_gs+4(%rip),%edx
wrmsr
```

此时我们通过`MSR_GS_BASE`指定了一个平台相关寄存器，然后将`initial_gs`的64-bit地址放到了`edx:eax`寄存器中，然后执行`wrmsr`指令，将`init_per_cpu__fixed_percpu_data`的基地址放入了`gs`寄存器，而这个地址将是中断栈的栈底地址。

### 2.3 设置默认中断处理函数

在此之后我们将进入`x86_64_start_kernel`函数的C语言代码中，此函数定义在[arch/x86/kernel/head64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head64.c#L425)。在这个函数中，我们将完成最后的准备工作，之后就要进入到与平台无关的通用内核代码。在这里，其中一项工作就是将中断服务程序入口地址填写到早期IDT中，如下：

```C
void __init idt_setup_early_handler(void)
{
    int i;

    for (i = 0; i < NUM_EXCEPTION_VECTORS; i++)
        set_intr_gate(i, early_idt_handler_array[i]);
#ifdef CONFIG_X86_32
    for ( ; i < NR_VECTORS; i++)
        set_intr_gate(i, early_ignore_irq);
#endif
    load_idt(&idt_descr);
}
```

`early_idt_handler_array`的定义如下：

```C
extern const char early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE];

...
#define NUM_EXCEPTION_VECTORS 32
#define EARLY_IDT_HANDLER_SIZE 9
```

因此，数组`early_idt_handler_array`存放着中断服务程序入口，其中每个入口占据9个字节。`early_idt_handler_array`在文件[arch/x86/kernel/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/head_64.S#L276)中定义，如下：

```C
ENTRY(early_idt_handler_array)
...
...
...
END(early_idt_handler_array)
```

这里使用`.rept NUM_EXCEPTION_VECTORS`循环填充`early_idt_handler_array`，其中也包含了`early_make_pgtable`和`early_fixup_exception`的中断处理函数入口(关于该中断服务函数的实现请参考内核初始化章节)。现在我们完成了所有x86-64平台相关的代码，即将进入通用内核代码中。

`set_intr_gate`函数设置每个中断向量的处理函数，实现如下：

```C
static void set_intr_gate(unsigned int n, const void *addr)
{
	struct idt_data data;

	BUG_ON(n > 0xFF);

	memset(&data, 0, sizeof(data));
	data.vector	= n;
	data.addr	= addr;
	data.segment	= __KERNEL_CS;
	data.bits.type	= GATE_INTERRUPT;
	data.bits.p	= 1;

	idt_setup_from_table(idt_table, &data, 1, false);
}
```

可以看到，`set_intr_gate`函数首先检查中断向量号`n`不大于`0xff`(或者255)；然后，根据向量号`n`和中断处理函数地址封装`struct idt_data`；最终，调用`idt_setup_from_table`设置封装后`data`。

## 3 禁用/启用本地中断

正如之前关于Linux内核初始化过程的章节，在`arch/x86/kernel/head64.c`之后的下一步进入到[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L575)中的`start_kernel`函数中。这个函数将完成内核第一个`init`进程（`pid`为1）之前的所有初始化工作。在`init/main.c`中与中断和中断处理相关的操作中，第一步是调用 `local_irq_disable`宏。

这个宏在[include/linux/irqflags.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irqflags.h#L109)头文件中定义，宏如其名，调用这个宏将禁用本地CPU的中断。我们来仔细了解一下这个宏的实现，首先，它依赖于内核配置选项`CONFIG_TRACE_IRQFLAGS`，如下：

```C
#ifdef CONFIG_TRACE_IRQFLAGS
#define local_irq_enable() \
    do { trace_hardirqs_on(); raw_local_irq_enable(); } while (0)
#define local_irq_disable() \
    do { raw_local_irq_disable(); trace_hardirqs_off(); } while (0)
...
#else /* !CONFIG_TRACE_IRQFLAGS */
#define local_irq_enable()    do { raw_local_irq_enable(); } while (0)
#define local_irq_disable()    do { raw_local_irq_disable(); } while (0)
...
#endif /* CONFIG_TRACE_IRQFLAGS */
```

这两者唯一的区别在于当`CONFIG_TRACE_IRQFLAGS`选项启用时，`local_irq_disable`宏将同时调用`trace_hardirqs_off`函数。在Linux死锁检测模块`lockdep`中有一项功能，   IRQ标记追踪（irq-flags tracing）可以追踪`hardirq`和`softirq`的状态。在这种情况下，`lockdep`死锁检测模块可以提供系统中关于硬中断和软中断的开/关事件的相关信息。`trace_hardirqs_off`函数在[kernel/trace/trace_preemptirq.c](https://github.com/torvalds/linux/blob/v5.4/kernel/trace/trace_preemptirq.c#L36)中实现，如下：

```C
void trace_hardirqs_off(void)
{
    if (!this_cpu_read(tracing_irq_cpu)) {
        this_cpu_write(tracing_irq_cpu, 1);
        tracer_hardirqs_off(CALLER_ADDR0, CALLER_ADDR1);
        if (!in_nmi())
            trace_irq_disable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
    }
    lockdep_hardirqs_off(CALLER_ADDR0);
}
EXPORT_SYMBOL(trace_hardirqs_off);
NOKPROBE_SYMBOL(trace_hardirqs_off);
```

首先检查`tracing_irq_cpu`变量，这个perCPU变量用来记录IRQ禁用的标志，预防重复的追踪调用；`tracer_hardirqs_off`函数在[kernel/trace/trace_irqsoff.c](https://github.com/torvalds/linux/blob/v5.4/kernel/trace/trace_irqsoff.c#L619)中实现，停止IRQ追踪；`lockdep_hardirqs_off`函数在[kernel/locking/lockdep.c](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/lockdep.c#L3442)中实现，该函数检查了当前进程的`hardirqs_enabled`字段，如果本次`local_irq_disable`调用是`ON -> OFF`转换时，增加`hardirq_disable_event`字段，否则，增加`redundant_hardirqs_off`字段。

`lockdep`统计的相关字段在[kernel/locking/lockdep_internals.h](https://github.com/torvalds/linux/blob/v5.4/kernel/locking/lockdep_internals.h#L168)中的`lockdep_stats`结构中定义，如下：

```C
struct lockdep_stats {
    ...
    unsigned long  hardirqs_on_events;
    unsigned long  hardirqs_off_events;
    unsigned long  redundant_hardirqs_on;
    ...
}
```

如果启用了`CONFIG_DEBUG_LOCKDEP`内核配置选项，`lockdep_stats_debug_show`函数会将所有的调试信息写入`/proc/lockdep`文件中，如下：

```C
static void lockdep_stats_debug_show(struct seq_file *m)
{
#ifdef CONFIG_DEBUG_LOCKDEP
    unsigned long long hi1 = debug_atomic_read(hardirqs_on_events),
               hi2 = debug_atomic_read(hardirqs_off_events),
               hr1 = debug_atomic_read(redundant_hardirqs_on),
    ...
    seq_printf(m, " hardirq on events:             %11llu\n", hi1);
    seq_printf(m, " hardirq off events:            %11llu\n", hi2);
    seq_printf(m, " redundant hardirq ons:         %11llu\n", hr1);
    seq_printf(m, " redundant hardirq offs:        %11llu\n", hr2);
    ...
#endif
}
```

你可以如下命令查看其内容:

```bash
$ sudo cat /proc/lockdep
hardirq on events:             12838248974
hardirq off events:            12838248979
redundant hardirq ons:               67792
redundant hardirq offs:         3836339146
softirq on events:                38002159
softirq off events:               38002187
redundant softirq ons:                   0
redundant softirq offs:                  0
```

现在我们了解到追踪函数`trace_hardirqs_off`的一些信息。`local_disable_irq`宏的实现中都包含了一个宏`raw_local_irq_disable`，在[arch/x86/include/asm/irqflags.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/irqflags.h#L87)中定义，最终展开后后如下:

```C
static inline void native_irq_disable(void)
{
    asm volatile("cli": : :"memory");
}
```

你可能还记得，`cli`指令将清除`IF`标志位，这个标志位控制着处理器是否响应中断或异常。与`local_irq_disable`相对的是`local_irq_enable`，这个宏的实现与`local_irq_disable`很相似，也具有相同的追踪机制，最终于使用`sti`指令启用中断:

```C
static inline void native_irq_enable(void)
{
        asm volatile("sti": : :"memory");
}
```

如今我们了解了`local_irq_disable`和`local_irq_enable`宏的实现机理。此处是首次调用`local_irq_disable`宏，我们还将在Linux内核源代码中多次看到它的身影。现在我们位于[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L575)中的`start_kernel`函数，并且刚刚禁用了本地中断。早期版本的内核中提供了一个叫做`cli`的函数来禁用所有处理器的中断，该函数已经被移除，替代它的是`local_irq_{enabled,disable}`宏，用于禁用或启用当前处理器的中断。

我们在调用`local_irq_disable`宏禁用中断以后，接着设置`early_boot_irqs_disabled = true`变量值，`early_boot_irqs_disabled`在[include/linux/kernel.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/kernel.h#L563)中声明，通过这个变量来标记当前是否处于中断状态，这个变量在另外的地方使用。例如在[kernel/smp.c](https://github.com/torvalds/linux/blob/v5.4/kernel/smp.c#L412)中的`smp_call_function_many`函数中，通过这个变量来检查当前是否由于中断禁用而处于死锁状态，如下：

```C
WARN_ON_ONCE(cpu_online(this_cpu) && irqs_disabled()
         && !oops_in_progress && !early_boot_irqs_disabled);
```

## 4 中断堆栈设置`Stack Canary`值

在中断处理设置完成后，在调用`local_irq_enable`函数启用中断前，调用`boot_init_stack_canary`函数。这个函数通过设置canary值来防止中断栈溢出。在上一章中我们已经初步了解了`boot_init_stack_canary`实现的一些细节，现在我们更进一步地认识它。 这个函数实现取决于`CONFIG_STACKPROTECTOR`内核配置选项，如果没有启用，该函数是一个空函数；否则在[arch/x86/include/asm/stackprotector.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/stackprotector.h#L61)中实现，如下：

```C
static __always_inline void boot_init_stack_canary(void)
{
    u64 canary;
    u64 tsc;

#ifdef CONFIG_X86_64
    BUILD_BUG_ON(offsetof(struct fixed_percpu_data, stack_canary) != 40);
#endif
    ...
    get_random_bytes(&canary, sizeof(canary));
    tsc = rdtsc();
    canary += tsc + (tsc << 32UL);
    canary &= CANARY_MASK;

    current->stack_canary = canary;
#ifdef CONFIG_X86_64
    this_cpu_write(fixed_percpu_data.stack_canary, canary);
#else
    this_cpu_write(stack_canary.canary, canary);
#endif
}
```

一开始将检查`fixed_percpu_data`的状态，这个结构体代表了per-cpu中断栈，其与`stack_canary`值中间有40个字节的偏移量；如之前章节所描述，`fixed_percpu_data`结构在[arch/x86/include/asm/processor.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/processor.h#L388)定义，如下:

```C
struct fixed_percpu_data {
    char        gs_base[40];
    unsigned long    stack_canary;
};
```

可以看到，第一个字段`gs_base`大小为40 bytes，指向了`irq_stack`的栈底。因此，当我们使用`BUILD_BUG_ON`对该表达式进行检查时结果应为成功。

紧接着我们使用随机数和时戳计数器计算新的`canary`值，并且通过`this_cpu_write`宏将`canary`值写入了`stack_canary`中。

## 5 早期`trap`中断处理

在`local_irq_enable`之后的`setup_arch`函数，很多架构相关的初始化工作。这个函数定义在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup.c#L837)文件中实现。在`setup_arch`函数中与中断相关的第一个函数是`idt_setup_early_traps`函数，在[arch/x86/kernel/idt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/idt.c#L253)中实现，填充了部分中断处理函数，如下：

```C
void __init idt_setup_early_traps(void)
{
    idt_setup_from_table(idt_table, early_idts, ARRAY_SIZE(early_idts),
                 true);
    load_idt(&idt_descr);
}
```

`early_idts`是个`idt_data`结构的数组，通过`INTG`和`SYSG`宏生成`idt_data`信息。`INTG`和`SYSG`这两个宏定义，展开后调用`G`宏。`G`宏按照参数组成`idt_data`结构，如下：

```C
static const __initconst struct idt_data early_idts[] = {
    INTG(X86_TRAP_DB,        debug),
    SYSG(X86_TRAP_BP,        int3),
#ifdef CONFIG_X86_32
    INTG(X86_TRAP_PF,        page_fault),
#endif
};
...
/* Interrupt gate */
#define INTG(_vector, _addr)                \
    G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL0, __KERNEL_CS)
/* System interrupt gate */
#define SYSG(_vector, _addr)                \
    G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL3, __KERNEL_CS)
```

### 5.1 中断处理函数的设置过程

`idt_setup_from_table`函数通过循环逐个将`idt_data`设置到`IDT`中，过程如下：

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

首先，调用`idt_init_desc`函数将`idt_data`转换为`gate_desc`，如下：

```C
static inline void idt_init_desc(gate_desc *gate, const struct idt_data *d)
{
    unsigned long addr = (unsigned long) d->addr;

    gate->offset_low    = (u16) addr;
    gate->segment        = (u16) d->segment;
    gate->bits        = d->bits;
    gate->offset_middle    = (u16) (addr >> 16);
#ifdef CONFIG_X86_64
    gate->offset_high    = (u32) (addr >> 32);
    gate->reserved        = 0;
#endif
}
```

然后，调用`write_idt_entry`宏写入`idt`中对应向量中；这个宏展开后是`native_write_idt_entry`，其将中断门信息通过索引拷贝到`idt_table`中:

```C
#define write_idt_entry(dt, entry, g)           native_write_idt_entry(dt, entry, g)
...
static inline void native_write_idt_entry(gate_desc *idt, int entry, const gate_desc *gate)
{
        memcpy(&idt[entry], gate, sizeof(*gate));
}
```

其中`idt_table`是一个`gate_desc`类型的数组，

```C
extern gate_desc idt_table[];
```

最后，如果是系统向量，修改`system_vectors`对应bit项。

### 5.2 早期IDT陷阱门设置

这里，我们调用`idt_setup_from_table`函数设置了`early_idts`。这里我们设置了`#DB`和`#BP`两个IDT处理函数。这就是`idt_setup_from_table`函数的全部内容。

## 6 结束语

本文描述了Linux内核的默认中断处理函数和早期陷阱门的设置，中断栈的介绍及禁用/启用中断的过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
