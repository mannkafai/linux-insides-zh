# 中断和中断处理 （第八部分）

## 0 IRQ中断初始化

在上一部分中，我们开始深入研究外部硬件中断。我们详细分析了`early_trap_init`函数的实现过程，该函数实现对`irq_desc`结构的初始化。`irq_desc`结构体用来表示一个中断描述符。本文我们继续深入分析外部硬件中断的初始化过程。

在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L674)中调用`early_irq_init`函数之后，调用`init_IRQ`函数。该函数基于特定架构，在[arch/x86/kernel/irqinit.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/irqinit.c#L79)中实现，如下：

```C
void __init init_IRQ(void)
{
	int i;
	for (i = 0; i < nr_legacy_irqs(); i++)
		per_cpu(vector_irq, 0)[ISA_IRQ_VECTOR(i)] = irq_to_desc(i);

	BUG_ON(irq_init_percpu_irqstack(smp_processor_id()));

	x86_init.irqs.intr_init();
}
```

## 1 传统IRQ向量初始化

`init_IRQ`函数首先初始化`vector_irq`percpu变量，`vector_irq`在同一个文件中定义，如下：

```C
DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
	[0 ... NR_VECTORS - 1] = VECTOR_UNUSED,
};
```

`vector_irq`表示percpu的中断向量表。`vector_irq_t`在[arch/x86/include/asm/hw_irq.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/hw_irq.h#L159)中定义，如下：

```C
#define VECTOR_UNUSED		NULL
...
typedef struct irq_desc* vector_irq_t[NR_VECTORS];
```

`NR_VECTORS`表示中断向量的数量，在`x86_64`下值为`256`。

因此，`init_IRQ`函数首先填充`vector_irq`数组中的传统中断。即：

```C
	for (i = 0; i < nr_legacy_irqs(); i++)
		per_cpu(vector_irq, 0)[ISA_IRQ_VECTOR(i)] = irq_to_desc(i);
```

`irq_to_desc`函数在[kernel/irq/irqdesc.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/irqdesc.c#L581)中实现，实现中断向量到中断描述符的映射。`vector_irq`在外部硬件中断处理程序`do_IRQ`中使用。

为什么是传统（legacy）？实际上现代`IO-APIC`控制器处理所有的中断，但`0x30 ~ 0x3f`之间的中断由传统的中断控制器（如：[可编程中断控制器](https://en.wikipedia.org/wiki/Programmable_Interrupt_Controller)）来处理。如果这些中断被IO-APIC处理后向量空间将被释放后重新使用。

`nr_legacy_irqs`函数在[arch/x86/include/asm/i8259.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/i8259.h#L78)中定义，仅仅返回`legacy_pic`结构中`nr_legacy_irqs`字段，如下：

```C
static inline int nr_legacy_irqs(void)
{
	return legacy_pic->nr_legacy_irqs;
}
```

`legacy_pic`变量在[arch/x86/kernel/i8259.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/i8259.c#L410)中定义，如下：

```C
struct legacy_pic default_legacy_pic = {
	.nr_legacy_irqs = NR_IRQS_LEGACY,
	.chip  = &i8259A_chip,
	.mask = mask_8259A_irq,
	.unmask = unmask_8259A_irq,
	.mask_all = mask_8259A,
	.restore_mask = unmask_8259A,
	.init = init_8259A,
	.probe = probe_8259A,
	.irq_pending = i8259A_irq_pending,
	.make_irq = make_8259A_irq,
};

struct legacy_pic *legacy_pic = &default_legacy_pic;
```

`struct legacy_pic`结构在同一个文件中定义，表示非现代可编程中断控制器，如下：

```C
struct legacy_pic {
	int nr_legacy_irqs;
	struct irq_chip *chip;
	void (*mask)(unsigned int irq);
	void (*unmask)(unsigned int irq);
	void (*mask_all)(void);
	void (*restore_mask)(void);
	void (*init)(int auto_eoi);
	int (*probe)(void);
	int (*irq_pending)(unsigned int irq);
	void (*make_irq)(unsigned int irq);
};
```

默认传统中断的最大数量使用`NR_IRQS_LEGACY`宏表示。在循环中我们使用`per-cpu`宏访问`vector_irq`数组，数组的索引使用`ISA_IRQ_VECTOR(i)`宏。`NR_IRQS_LEGACY`宏和`ISA_IRQ_VECTOR`宏在[arch/x86/include/asm/irq_vectors.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/irq_vectors.h#L128)中定义，如下：

```C
#define FIRST_EXTERNAL_VECTOR		0x20
#define ISA_IRQ_VECTOR(irq)		(((FIRST_EXTERNAL_VECTOR + 16) & ~15) + irq)

...
#define NR_IRQS_LEGACY			16
```

第一个`ISA_IRQ_VECTOR`，即：`ISA_IRQ_VECTOR(0)`，展开后值为`0x30`。为什么是`0x30`？在本章的开始，向量号`0~31`的前32个中断向量被处理器预留，用于CPU架构相关的中断和异常处理。中断向量号`0x30 ~ 0x3f`被[ISA](https://en.wikipedia.org/wiki/Industry_Standard_Architecture)预留。

所以，这就意味着我们填充`0x30 ~ 0x3f`之间的`vector_irq`。

## 2 CPU架构IRQ向量初始化

接下来，我们调用`x86_init.irqs.intr_init();`函数初始化CPU架构相关IRQ。`x86_init`在[arch/x86/kernel/x86_init.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/x86_init.c#L57)中定义，这个结构包含平台架构相关的平台设置，如：`resources` - 内存资源相关设置，`mpparse` - 与多处理器配置表解析相关。同样，`x86_init`包含`irqs`字段，如下：

```C
struct x86_init_ops x86_init __initdata = {
    ...
    	.irqs = {
		.pre_vector_init	= init_ISA_irqs,
		.intr_init		= native_init_IRQ,
		.trap_init		= x86_init_noop,
		.intr_mode_select	= apic_intr_mode_select,
		.intr_mode_init		= apic_intr_mode_init
	},
    ...
};
```

可以看到`x86_init.irqs.intr_init();`即`native_init_IRQ`函数。`native_init_IRQ`函数在[arch/x86/kernel/irqinit.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/irqinit.c#L99)中实现，如下：

```C
void __init native_init_IRQ(void)
{
	x86_init.irqs.pre_vector_init();

	idt_setup_apic_and_irq_gates();
	lapic_assign_system_vectors();

	if (!acpi_ioapic && !of_ioapic && nr_legacy_irqs())
		setup_irq(2, &irq2);
}
```

### 2.1 ISA中断初始化

可以看到，`native_init_IRQ`函数首先调用`x86_init.irqs.pre_vector_init()`函数，在上面我们可以看到`pre_vector_init`指向`init_ISA_irqs`函数。该函数在同一个文件中实现，我们可以通过函数名称理解函数功能，该函数初始化ISA相关中断。实现过程如下：

```C
void __init init_ISA_irqs(void)
{
	struct irq_chip *chip = legacy_pic->chip;
	int i;

	init_bsp_APIC();

	legacy_pic->init(0);

	for (i = 0; i < nr_legacy_irqs(); i++)
		irq_set_chip_and_handler(i, chip, handle_level_irq);
}
```

`irq_set_chip_and_handler`函数在[include/linux/irq.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irq.h#L650)中定义，该函数调用`irq_set_chip_and_handler_name`函数，后者在[kernel/irq/chip.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/chip.c#L1086)中实现，根据函数名称可知道，该函数设置`irq`中断的芯片、处理函数和名称。如下：

```C
static inline void irq_set_chip_and_handler(unsigned int irq, struct irq_chip *chip,
					    irq_flow_handler_t handle)
{
	irq_set_chip_and_handler_name(irq, chip, handle, NULL);
}

void
irq_set_chip_and_handler_name(unsigned int irq, struct irq_chip *chip,
			      irq_flow_handler_t handle, const char *name)
{
	irq_set_chip(irq, chip);
	__irq_set_handler(irq, handle, 0, name);
}
```

`irq_set_chip`函数设置`irq`芯片字段，如下：

```C
int irq_set_chip(unsigned int irq, struct irq_chip *chip)
{
	unsigned long flags;
	struct irq_desc *desc = irq_get_desc_lock(irq, &flags, 0);
	...
	if (!chip)
		chip = &no_irq_chip;

	desc->irq_data.chip = chip;
	...
}
```

`__irq_set_handler`函数调用`__irq_do_set_handler`函数设置`irq`的`handle_irq`和`name`字段。如下：

```C
static void
__irq_do_set_handler(struct irq_desc *desc, irq_flow_handler_t handle,
		     int is_chained, const char *name)
{
	...
	...
	desc->handle_irq = handle;
	desc->name = name;
	...
	...
}
```

通过传递`irq_set_chip_and_handler`的参数可以知道，`chip`为`legacy_pic->chip`，`handle`为`handle_level_irq`。即：传统IRQ的`handle_irq`均为`handle_level_irq`。

#### 2.1.1 关键结构体说明

`irq_chip`结构体在[include/linux/irq.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irq.h#L449)中定义，用来描述硬件中断芯片描述符。包括如下字段：

* `name` - 设备名称。通过`/proc/interrupts`输出的最后一列可以看到；
* `(*irq_startup)(struct irq_data *data)` - 中断设置的操作；
* `(*irq_shutdown)(struct irq_data *data)` - 中断关闭的操作；
* `(*irq_mask)(struct irq_data *data)` - 中断屏蔽的操作；
* `(*irq_ack)(struct irq_data *data)` - 开始新中断的操作；
* ...

`struct irq_data`结构表示传递到信号函数的每次irq芯片数据。`irq_data`结构体同样在[include/linux/irq.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/irq.h#L173)中定义，包含如下字段：

* `mask` - 预先计算的访问芯片寄存器的掩码；
* `irq` - 中断号；
* `hwirq` - 硬件中断号，定位到中断域；
* `chip` - 低级中断硬件访问使用；
* ...

#### 2.1.2 启动处理器的APIC初始化

接下来，调用`init_bsp_APIC`函数初始化启动处理器(bootstrap processor)的APIC，`init_bsp_APIC`函数在[arch/x86/kernel/apic/apic.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/apic.c#L1390)中实现。

首先，在检查到SMP配置和处理器包含APIC时，直接返回；如下：

```C
	if (smp_found_config || !boot_cpu_has(X86_FEATURE_APIC))
		return;
```

接下来，调用`clear_local_APIC`函数清除本地APIC；之后，通过设置`APIC_SPIV_APIC_ENABLED`值来开启第一个处理器的`APIC`，如下：

```C
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;
	value |= APIC_SPIV_APIC_ENABLED;
```

最后，通过`apic_write`函数写入：

```C
	apic_write(APIC_SPIV, value);
```

#### 2.1.3 传统PIC初始化

接下来，调用`legacy_pic->init(0);`函数，该函数初始化传统PIC。`legacy_pic->init`函数，即`init_8259A`函数，在[arch/x86/kernel/i8259.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/i8259.c#L327)中实现。该函数初始化[Intel 8259](https://en.wikipedia.org/wiki/Intel_8259)可编程中断控制器(Programable Interrupt Controll，PIC)。

最后，设置每个传统irq的芯片和中断处理程序。`chip`为`legacy_pic->chip`，即`i8259A_chip`，在[arch/x86/kernel/i8259.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/i8259.c#L224)中定义；`handler`为`handle_level_irq`，在[kernel/irq/chip.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/chip.c#L630)实现。

### 2.2 IRQ中断门设置

接下来，返回到`native_init_IRQ`函数。下一个调用的函数是`idt_setup_apic_and_irq_gates`，在[arch/x86/kernel/idt.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/idt.c#L307)中实现。如下：

```C
void __init idt_setup_apic_and_irq_gates(void)
{
	int i = FIRST_EXTERNAL_VECTOR;
	void *entry;

	idt_setup_from_table(idt_table, apic_idts, ARRAY_SIZE(apic_idts), true);

	for_each_clear_bit_from(i, system_vectors, FIRST_SYSTEM_VECTOR) {
		entry = irq_entries_start + 8 * (i - FIRST_EXTERNAL_VECTOR);
		set_intr_gate(i, entry);
	}

#ifdef CONFIG_X86_LOCAL_APIC
	for_each_clear_bit_from(i, system_vectors, NR_VECTORS) {
		entry = spurious_entries_start + 8 * (i - FIRST_SYSTEM_VECTOR);
		set_intr_gate(i, entry);
	}
#endif
}
```

在[arch/x86/include/asm/irq_vectors.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/irq_vectors.h#L18)中我们可以看到中断向量的整体分布情况，如下：

* 0  ---  31    ：系统陷阱和异常中断门；
* 32 --- 127    ：设备中断；
* 128           ：传统的int80系统调用中断
* 129 -- LOCAL_TIMER_VECTOR-1   ：
* LOCAL_TIMER_VECTOR ... 255    ： 特殊中断

#### 2.2.1 APIC中断表设置

首先，调用`idt_setup_from_table`函数设置`apic_idts`中断。`apic_idts`在同一个文件中定义，如下：

```C
static const __initconst struct idt_data apic_idts[] = {
#ifdef CONFIG_SMP
	INTG(RESCHEDULE_VECTOR,		reschedule_interrupt),
	INTG(CALL_FUNCTION_VECTOR,	call_function_interrupt),
	INTG(CALL_FUNCTION_SINGLE_VECTOR, call_function_single_interrupt),
	INTG(IRQ_MOVE_CLEANUP_VECTOR,	irq_move_cleanup_interrupt),
	INTG(REBOOT_VECTOR,		reboot_interrupt),
#endif

    ...

#ifdef CONFIG_X86_LOCAL_APIC
	INTG(LOCAL_TIMER_VECTOR,	apic_timer_interrupt),
	INTG(X86_PLATFORM_IPI_VECTOR,	x86_platform_ipi),
    ...
    ...
	INTG(SPURIOUS_APIC_VECTOR,	spurious_interrupt),
	INTG(ERROR_APIC_VECTOR,		error_interrupt),
#endif
};
```

#### 2.2.2 IRQ中断表设置

接下来，设置IRQ中断表。如下：

```C
	for_each_clear_bit_from(i, system_vectors, FIRST_SYSTEM_VECTOR) {
		entry = irq_entries_start + 8 * (i - FIRST_EXTERNAL_VECTOR);
		set_intr_gate(i, entry);
	}
```

`irq_entries_start`在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L367)定义，如下：

```C
	.align 8
ENTRY(irq_entries_start)
    vector=FIRST_EXTERNAL_VECTOR
    .rept (FIRST_SYSTEM_VECTOR - FIRST_EXTERNAL_VECTOR)
	UNWIND_HINT_IRET_REGS
	pushq	$(~vector+0x80)			/* Note: always in signed byte range */
	jmp	common_interrupt
	.align	8
	vector=vector+1
    .endr
END(irq_entries_start)
```

即，`irq_entries_start`是一个数组，数组中每个项8个字节，包含：1字节的中断向量和一个跳转地址。`FIRST_EXTERNAL_VECTOR`和`FIRST_SYSTEM_VECTOR`在[arch/x86/include/asm/irq_vectors.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/irq_vectors.h#L36)中定义，如下：

```C
#define FIRST_EXTERNAL_VECTOR		0x20

#define LOCAL_TIMER_VECTOR		0xec
#define NR_VECTORS			 256

#ifdef CONFIG_X86_LOCAL_APIC
#define FIRST_SYSTEM_VECTOR		LOCAL_TIMER_VECTOR
#else
#define FIRST_SYSTEM_VECTOR		NR_VECTORS
#endif
```

可以看到`irq_entries_start`数组的数量依赖于`CONFIG_X86_LOCAL_APIC`内核配置选项，值为`224`(256-0x20，未开启的情况)或者`204`(0xec-0x20)。`for_each_clear_bit_from`是宏定义，只返回未填充的bit。`system_vectors`变量是个bitmap，定义如下：

```C
DECLARE_BITMAP(system_vectors, NR_VECTORS);
```

因此，设置IRQ中断过程为，将`FIRST_EXTERNAL_VECTOR`和`FIRST_SYSTEM_VECTOR`之间之前没有设置的中断向量进行设置，设置的中断处理程序为`common_interrupt`。

#### 2.2.3 IRQ中断处理过程

IRQ中断设置的中断处理程序为`common_interrupt`，在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L603)中定义，如下：

```C
	.p2align CONFIG_X86_L1_CACHE_SHIFT
common_interrupt:
	addq	$-0x80, (%rsp)			/* Adjust vector to [-256, -1] range */
	call	interrupt_entry
	UNWIND_HINT_REGS indirect=1
	call	do_IRQ	/* rdi points to pt_regs */
	/* 0(%rsp): old RSP */
ret_from_intr:
	DISABLE_INTERRUPTS(CLBR_ANY)
	TRACE_IRQS_OFF

	LEAVE_IRQ_STACK

	testb	$3, CS(%rsp)
	jz	retint_kernel

	/* Interrupt came from user space */
GLOBAL(retint_user)
    ...
```

##### 2.2.3.1 进入中断

可以看到，在调整中断向量后调用`interrupt_entry`宏，在同一个汇编文件中定义，如下：

```C
ENTRY(interrupt_entry)
	UNWIND_HINT_IRET_REGS offset=16
	ASM_CLAC
	cld

	testb	$3, CS-ORIG_RAX+8(%rsp)
	jz	1f
    ...
1:
	FENCE_SWAPGS_KERNEL_ENTRY
2:
	PUSH_AND_CLEAR_REGS save_ret=1
	ENCODE_FRAME_POINTER 8

	testb	$3, CS+8(%rsp)
	jz	1f
    ...

1:
	ENTER_IRQ_STACK old_rsp=%rdi save_ret=1
	/* We entered an interrupt context - irqs are off: */
	TRACE_IRQS_OFF

	ret
END(interrupt_entry)
```

首先，通过`testb	$3, CS-ORIG_RAX+8(%rsp)`判断当前处于用户模式还是内核模式。当处于内核模式时，直接跳转到`FENCE_SWAPGS_KERNEL_ENTRY`处继续执行，后续执行主要包括：`PUSH_AND_CLEAR_REGS`(保存调用堆栈)、`ENTER_IRQ_STACK`(进入IRQ栈)、`TRACE_IRQS_OFF`(关闭IRQ追踪)。

当处于用户模式时，需要切换栈空间，如下：

```C
	SWAPGS
	FENCE_SWAPGS_USER_ENTRY

	pushq	%rdi

	/* Need to switch before accessing the thread stack. */
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rdi
	movq	%rsp, %rdi
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp
```

保存跳转栈的寄存器，如下：

```C
	UNWIND_HINT_IRET_REGS base=%rdi offset=24

	pushq	7*8(%rdi)		/* regs->ss */
	pushq	6*8(%rdi)		/* regs->rsp */
	pushq	5*8(%rdi)		/* regs->eflags */
	pushq	4*8(%rdi)		/* regs->cs */
	pushq	3*8(%rdi)		/* regs->ip */
	UNWIND_HINT_IRET_REGS
	pushq	2*8(%rdi)		/* regs->orig_ax */
	pushq	8(%rdi)			/* return address */

	movq	(%rdi), %rdi
```

此时的栈分布如下：

```text
 +----------------------------------------------------+
 | regs->ss						|
 | regs->rsp						|
 | regs->eflags					|
 | regs->cs						|
 | regs->ip						|
 +----------------------------------------------------+
 | regs->orig_ax = ~(interrupt number)		|
 +----------------------------------------------------+
 | return address					|
 +----------------------------------------------------+
```

在调用`PUSH_AND_CLEAR_REGS`宏保存调用寄存器值后，调用`enter_from_user_mode`函数，之后调用`ENTER_IRQ_STACK`(进入IRQ栈)、`TRACE_IRQS_OFF`(关闭IRQ追踪)。

##### 2.2.3.2 中断处理

执行`call	do_IRQ`，调用`do_IRQ`函数执行IRQ中断处理。`do_IRQ`函数在[arch/x86/kernel/irq.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/irq.c#L233)实现，如下：

```C
__visible unsigned int __irq_entry do_IRQ(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);
	struct irq_desc * desc;
	unsigned vector = ~regs->orig_ax;

	entering_irq();
	RCU_LOCKDEP_WARN(!rcu_is_watching(), "IRQ failed to wake up RCU");

	desc = __this_cpu_read(vector_irq[vector]);
	if (likely(!IS_ERR_OR_NULL(desc))) {
		if (IS_ENABLED(CONFIG_X86_32))
			handle_irq(desc, regs);
		else
			generic_handle_irq_desc(desc);
	} else {
		ack_APIC_irq();
        ...
	}
	exiting_irq();
	set_irq_regs(old_regs);
	return 1;
}
```

`do_IRQ`函数执行过程可以分成三个部分，进入IRQ、执行IRQ、退出IRQ。

* 进入IRQ的执行过程，包括：`set_irq_regs`(保存当前寄存器)、`entering_irq`(进入IRQ的准备工作，主要是禁用软中断的下半部分)；
* 执行IRQ中断过程包括：根据中断向量获取`irq_desc`中断描述符，调用`generic_handle_irq_desc`函数执行中断，最终调用`desc->handle_irq(desc)`（即：中断描述符中的中断处理函数），或者调用`ack_APIC_irq`函数（默认中断处理程序）；
* 退出IRQ的执行过程，包括：`exiting_irq`(退出IRQ的工作，主要是存在软中断时调用软中断)，`set_irq_regs`(恢复旧寄存器)；

##### 2.2.3.3 中断退出

在中断执行完成后，返回到`ret_from_intr`标签继续执行，如下：

```C
ret_from_intr:
	DISABLE_INTERRUPTS(CLBR_ANY)
	TRACE_IRQS_OFF

	LEAVE_IRQ_STACK

	testb	$3, CS(%rsp)
	jz	retint_kernel

	/* Interrupt came from user space */
GLOBAL(retint_user)
```

首先，恢复中断调用栈，包括：`DISABLE_INTERRUPTS`(即:`cli`，禁用所有的中断)、`TRACE_IRQS_OFF`(停止IRQ追踪)、`LEAVE_IRQ_STACK`(离开IRQ调用栈)。

然后，根据`%CS`寄存器判断当前状态。处于用户模式时，调用`retint_user`返回用户空间；处于内核模式时，调用`retint_kernel`返回内核空间。

#### 2.2.4 本地APIC中断表设置

接下来，设置本地APIC中断表，该功能取决于`CONFIG_X86_LOCAL_APIC`内核配置选项。如下：

```C
#ifdef CONFIG_X86_LOCAL_APIC
	for_each_clear_bit_from(i, system_vectors, NR_VECTORS) {
		entry = spurious_entries_start + 8 * (i - FIRST_SYSTEM_VECTOR);
		set_intr_gate(i, entry);
	}
#endif
```

整体的实现过程和上节中IRQ实现过程一致，只有中断表不同。`spurious_entries_start`同样在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L379)中实现。如下：

```C
	.align 8
ENTRY(spurious_entries_start)
    vector=FIRST_SYSTEM_VECTOR
    .rept (NR_VECTORS - FIRST_SYSTEM_VECTOR)
	UNWIND_HINT_IRET_REGS
	pushq	$(~vector+0x80)			/* Note: always in signed byte range */
	jmp	common_spurious
	.align	8
	vector=vector+1
    .endr
END(spurious_entries_start)
```

`spurious_entries_start`数组的数量依赖于`CONFIG_X86_LOCAL_APIC`内核配置选项，值为`0`(未开启的情况)或者`20`(256 -0xec)。调用的中断处理程序为`common_spurious`，如下：

```C
common_spurious:
	addq	$-0x80, (%rsp)			/* Adjust vector to [-256, -1] range */
	call	interrupt_entry
	UNWIND_HINT_REGS indirect=1
	call	smp_spurious_interrupt		/* rdi points to pt_regs */
	jmp	ret_from_intr
END(common_spurious)
_ASM_NOKPROBE(common_spurious)
```

可以看到，`common_spurious`和`common_interrupt`处理过程一致，只有调用中断函数的区别。`common_spurious`宏调用`smp_spurious_interrupt`函数，后者在[arch/x86/kernel/apic/apic.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/apic.c#L2151)中实现。

### 2.3 IRQ中断分配系统中断向量

在设置APIC中断后，调用`lapic_assign_system_vectors`函数分配系统中断向量，该函数在[arch/x86/kernel/apic/vector.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/apic/vector.c#L677)中实现。根据中断向量号设置`vector_matrix`，`vector_matrix`限定中断的查询区域。

### 2.4 设置级联设备中断

在最后，检查条件满足的条件下设置级联设备中断。如下：

```C
	if (!acpi_ioapic && !of_ioapic && nr_legacy_irqs())
		setup_irq(2, &irq2);
```

#### 2.4.1 条件检查

`acpi_ioapic`变量表示是否存在[I/O APIC](https://en.wikipedia.org/wiki/Advanced_Programmable_Interrupt_Controller#I.2FO_APICs)，在[arch/x86/kernel/acpi/boot.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/acpi/boot.c#L52)中定义。在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup.c#L1250)中初始化平台架构阶段，在`acpi_boot_init`函数中解析MADT(Multiple APIC Description Table)时调用`acpi_set_irq_model_ioapic`函数时设置。`acpi_ioapic`变量依赖于`CONFIG_ACPI`和`CONFIG_X86_LOCAL_APIC`内核配置选项，如果这些选项没有设置时，该变量设置为`0`:

```C
#ifdef CONFIG_ACPI
extern int acpi_ioapic;
...
#else
#define acpi_ioapic 0
...
#endif
```

`of_ioapic`变量表示是否使用[开放固件(Open Firmware)](https://en.wikipedia.org/wiki/Open_Firmware)的`I/O APIC`，在[arch/x86/kernel/devicetree.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/devicetree.c#L31)中定义。在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup.c#L1252)中初始化平台架构阶段，在`x86_dtb_init`函数中设备树中构建APIC时调用`dtb_ioapic_setup`函数时设置。`of_ioapic`变量依赖于`CONFIG_OF`内核配置选项，如果选项没有设置时，该变量设置为`0`:

```C
#ifdef CONFIG_OF
extern int of_ioapic;
...
#else
#define of_ioapic 0
...
#endif
```

`nr_legacy_irqs`函数返回值，表示是否使用传统中断控制器。

#### 2.4.2 设置级联中断

在上述三个条件都满足的条件下，执行`setup_irq(2, &irq2)`设置中断。

`irq2`变量的类型是`struct irqaction`，表示用来查询设备级联关系的`IRQ 2`中断线，在[arch/x86/kernel/irqinit.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/irqinit.c#L50)中定义，如下：

```C
static struct irqaction irq2 = {
	.handler = no_action,
	.name = "cascade",
	.flags = IRQF_NO_THREAD,
};
```

`struct irqaction`结构在[include/linux/interrupt.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/interrupt.h#L110)中定义，表示中断操作描述符。

之前中断控制器由两个芯片组成，一个芯片连接到另一个芯片。第二个芯片通过`IRQ 2`中断线连接到第一个芯片，在连接到第一个芯片后，只提供`8 ~ 15`中断线。以[Intel 8259](https://en.wikipedia.org/wiki/Intel_8259)为例，包含下列中断线：

* IRQ 0  - 系统时间;
* IRQ 1  - 键盘;
* IRQ 2  - 级联设备连接;
* IRQ 3  - COM2 and COM4;
* IRQ 4  - COM1 and COM3;
* IRQ 5  - LPT2;
* IRQ 6  - 驱动控制器;
* IRQ 7  - LPT1；
* IRQ 8  - [实时时钟(RTC)](https://en.wikipedia.org/wiki/Real-time_clock);
* IRQ 9  - 预留;
* IRQ 10 - 预留;
* IRQ 11 - 预留;
* IRQ 12 - PS/2 鼠标;
* IRQ 13 - 协同处理器;
* IRQ 14 - 主硬盘控制器;
* IRQ 15 - 备硬盘控制器。

`setup_irq`函数在[kernel/irq/manage.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/manage.c#L1661)中实现，需要两个参数：`irq` - 中断向量；`act` - 中断操作描述符。如下：

```C
int setup_irq(unsigned int irq, struct irqaction *act)
{
	int retval;
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc || WARN_ON(irq_settings_is_per_cpu_devid(desc)))
		return -EINVAL;

	retval = irq_chip_pm_get(&desc->irq_data);
	if (retval < 0)
		return retval;

	retval = __setup_irq(irq, desc, act);

	if (retval)
		irq_chip_pm_put(&desc->irq_data);

	return retval;
}
```

`irq_chip_pm_get`和`irq_chip_pm_put`这对函数在[kernel/irq/chip.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/chip.c#L1557)中实现，用于给IRQ芯片供电/断电。在这两个函数之间调用`__setup_irq`函数设置中断。

`__setup_irq`函数做了许多不同的事情，如：在提供线程函数时，但不嵌套到另外的线程时创建新的线程；设置芯片标记；填充`irqaction`结构等等。

经过上面的步骤后，会创建`/proc/vector_number`目录结构并填充，使用现代计算机时，通过APIC处理中断，这些值都将是零。

```bash
$ cat /proc/irq/2/node
0

$cat /proc/irq/2/affinity_hint 
00

cat /proc/irq/2/spurious 
count 0
unhandled 0
last_unhandled 0 ms
```

## 3 结束语

本文继续深入分析外部中断的实现过程，分析了`init_IRQ`函数的实现过程。在其中我们分析了IRQ中断表初始化过程，包括：传统IRQ中断初始化、APIC中断初始化等；分析了IRQ中断的实现过程和IRQ的设置过程。在接下来的部分，我们继续深入学习中断的内容，即将看到软中断(softirqs)。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
