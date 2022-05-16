# 中断和中断处理 （第十部分）

## 0 介绍

在上一部分中，我们详细分析了延后中断及其相关概念，包括：`softirq`，`tasklet`，`workqueue`。本节我们继续深入这个主题，现在是见识真正的硬件驱动的时候了。

以[StringARM** SA-100/21285 评估板](http://netwinder.osuosl.org/pub/netwinder/docs/intel/datashts/27813501.pdf)串行驱动为例，我们来观察驱动程序如何请求一个[IRQ](https://en.wikipedia.org/wiki/Interrupt_request_%28PC_architecture%29)线，以及一个中断被触发时会发生什么。驱动程序代码位于[drivers/tty/serial/21285.c](https://github.com/torvalds/linux/blob/v5.4/drivers/tty/serial/21285.c#L502)源文件。

## 1 内核模块的初始化

与本书其他新概念类似，为了考察这个驱动程序，我们从考察它的初始化过程开始。如你所知，Linux内核为驱动程序或者内核模块的初始化和终止提供了两个宏：

* `module_init`
* `module_exit`

可以在驱动程序的源代码中可以找到这些宏的用法:

```C
module_init(serial21285_init);
module_exit(serial21285_exit);
```

大多数驱动程序都能编译成一个可装载的内核[模块](https://en.wikipedia.org/wiki/Loadable_kernel_module)，或者静态链接到Linux内核中。前一种情况下，设备驱动程序的初始化由`module_init`与`module_exit`宏触发。这些宏在[include/linux/module.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/module.h#L127)中定义，如下：

```C
#define module_init(initfn)					\
	static inline initcall_t __maybe_unused __inittest(void)		\
	{ return initfn; }					\
	int init_module(void) __copy(initfn) __attribute__((alias(#initfn)));

#define module_exit(exitfn)					\
	static inline exitcall_t __maybe_unused __exittest(void)		\
	{ return exitfn; }					\
	void cleanup_module(void) __copy(exitfn) __attribute__((alias(#exitfn)));
```

并被`initcall`函数调用：

* `early_initcall`
* `pure_initcall`
* `core_initcall`
* `postcore_initcall`
* `arch_initcall`
* `subsys_initcall`
* `fs_initcall`
* `rootfs_initcall`
* `device_initcall`
* `late_initcall`

这些函数被[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L1009)中的`do_initcalls`函数调用。然而，如果设备驱动程序被静态链接到Linux内核，那么这些宏的实现如下：

```C
#define module_init(x)  __initcall(x);
#define module_exit(x)  __exitcall(x);
```

这种情况下，模块装载的实现位于[kernel/module.c](https://github.com/torvalds/linux/blob/v5.4/kernel/module.c#L3555)源文件中，在`do_init_module`函数中进行初始化。我们不打算在本章深入探讨可装载模块的细枝末节，而会在一个专门介绍Linux内核模块的章节中窥其真容。话说回来，`module_init`宏接受一个参数 - 本例中这个值是`serial21285_init`，从函数名可以得知，这个函数完成一些驱动程序初始化的相关工作。如下：

```C
static int __init serial21285_init(void)
{
	int ret;

	printk(KERN_INFO "Serial: 21285 driver\n");

	serial21285_setup_ports();

	ret = uart_register_driver(&serial21285_reg);
	if (ret == 0)
		uart_add_one_port(&serial21285_reg, &serial21285_port);

	return ret;
}
```

如你所见，首先它把驱动程序相关信息写入内核缓冲区，然后调用`serial21285_setup_ports`函数。该函数设置了 `serial21285_port`设备的基本[uart](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver/transmitter)时钟：

```C
unsigned int mem_fclk_21285 = 50000000;

static void serial21285_setup_ports(void)
{
	serial21285_port.uartclk = mem_fclk_21285 / 4;
}
```

`serial21285`是描述`uart`驱动程序的结构体：

```C
static struct uart_driver serial21285_reg = {
	.owner			= THIS_MODULE,
	.driver_name	= "ttyFB",
	.dev_name		= "ttyFB",
	.major			= SERIAL_21285_MAJOR,
	.minor			= SERIAL_21285_MINOR,
	.nr			    = 1,
	.cons			= SERIAL_21285_CONSOLE,
};
```

接下来，调用`uart_register_driver`函数注册驱动程序。如果注册成功，调用`uart_add_one_port`函数添加由驱动程序定义的端口`serial21285_port`结构体，然后从`serial21285_init`函数返回：

```C
if (ret == 0)
	uart_add_one_port(&serial21285_reg, &serial21285_port);

return ret;
```

`uart_register_driver`和`uart_add_one_port`函数都在[drivers/tty/serial/serial_core.c](https://github.com/torvalds/linux/blob/v5.4/drivers/tty/serial/serial_core.c#L2787)中实现。到此为止，我们的驱动程序初始化完毕。

当一个`uart`端口被[drivers/tty/serial/serial_core.c](https://github.com/torvalds/linux/blob/v5.4/drivers/tty/serial/serial_core.c#L1769)中的`uart_open`函数打开时调用`tty_port_open`函数，`tty_port_open`函数调用`port->ops->activate`接口(设置为`uart_port_activate`函数），`uart_port_activate`函数会调用`uart_startup`函数来启动这个串行端口，后者会调用`startup`函数。它是`uart_ops`结构体的一部分，每个`uart`驱动程序都会定义这样一个结构体。在本例中，它是这样的：

```C
static struct uart_ops serial21285_ops = {
	...
	.startup	= serial21285_startup,
	...
}
```

可以看到`.startup`字段是对`serial21285_startup`函数的引用。这个函数的实现是我们的关注重点，因为它与中断和中断处理密切相关。

## 2 请求中断线

我们来看看`serial21285_startup`函数的实现：

```C
static int serial21285_startup(struct uart_port *port)
{
	int ret;

	tx_enabled(port) = 1;
	rx_enabled(port) = 1;

	ret = request_irq(IRQ_CONRX, serial21285_rx_chars, 0,
			  serial21285_name, port);
	if (ret == 0) {
		ret = request_irq(IRQ_CONTX, serial21285_tx_chars, 0,
				  serial21285_name, port);
		if (ret)
			free_irq(IRQ_CONRX, port);
	}

	return ret;
}
```

### 2.1 `TX`和`RX`中断线

首先是`TX`和`RX`，设备的串行总线仅由两条线组成：一条用于发送数据，另一条用于接收数据。与此对应，串行设备应该有两个串行引脚：接收器(`RX`)和发送器(`TX`)，通过调用`tx_enabled`和`rx_enalbed`这两个宏来激活这些线。函数接下来的部分是我们最感兴趣的。注意`request_irq`这个函数，它注册了一个中断处理程序，并激活给定的中断线。我们看一下这个函数的实现细节，该函数在[include/linux/interrupt.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/interrupt.h#L144)头文件中定义，如下所示：

```C
static inline int __must_check
request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
            const char *name, void *dev)
{
        return request_threaded_irq(irq, handler, NULL, flags, name, dev);
}
```

可以看到，`request_irq`函数接受五个参数：

* `irq` - 被请求的中断号；
* `handler` - 中断处理程序的函数指针；
* `flags` - 掩码选项；
* `name` - 中断拥有者的名称；
* `dev` - 中断处理函数的参数；
  
以我们的例子来分析`request_irq`函数的调用。可以看到，第一个参数是`IRQ_CONRX`，我们知道它是中断号，在[arch/arm/mach-footbridge/include/mach/irqs.h](https://github.com/torvalds/linux/blob/v5.4/arch/arm/mach-footbridge/include/mach/irqs.h#L26)头文件中定义。我们可以在这里找到`21285`主板能够产生的全部中断。在第二次调用`request_irq`函数时，我们传入了`IRQ_CONTX`中断号。我们的驱动程序会在这些中断中处理`RX`和`TX`事件。这些宏定义如下：

```C
#define _DC21285_IRQ(x)         (16 + (x))
...
...
...
#define IRQ_CONRX               _DC21285_IRQ(0)
#define IRQ_CONTX               _DC21285_IRQ(1)
```

这个主板的[ISA](https://en.wikipedia.org/wiki/Industry_Standard_Architecture)中断号分布在`0~15`这个范围内。因此，我们的中断号就是在此之后的头两个值：`16`和`17`。在`request_irq`函数的两次调用中，第二个参数分别是 `serial21285_rx_chars`和`serial21285_tx_chars`函数。当`RX`或`TX`中断发生时，这些函数就会被调用。我们不会在此深入探究这些函数，因为本章讲述的是中断与中断处理，而并非设备和驱动。下一个参数是`flags`，`request_irq`函数的两次调用中，它的值都是零。所有可用的`flags`在[include/linux/interrupt.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/interrupt.h#L65)中定义的类似`IRQF_*`这类的宏。例如：

* IRQF_SHARED - 允许多个设备共享此中断号
* IRQF_PERCPU - 此中断号属于单独cpu的(per cpu)
* IRQF_NO_THREAD - 中断不能线程化
* IRQF_NOBALANCING - 此中断步参与irq平衡时
* IRQF_IRQPOLL - 此中断用于轮询
* ...

这里，我们传入的是`0`，也就是`IRQF_TRIGGER_NONE`。这个标志是说，它不配置任何水平触发或边缘触发的中断行为。至于第四个参数(name)，我们传入`serial21285_name`，它定义如下：

```C
static const char serial21285_name[] = "Footbridge UART";
```

它会显示在`/proc/interrupts`的输出中。针对最后一个参数，我们传入一个指向`uart_port`结构体的指针。

### 2.2 设置中断前的检查

对`request_irq`函数及其参数有所了解后，我们来看看它的实现。从上文可以看到，`request_irq`函数内部只是调用了`request_threaded_irq`函数，该函数在[kernel/irq/manage.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/manage.c#L1974)文件中实现，如下：

```C
int request_threaded_irq(unsigned int irq, irq_handler_t handler,
			 irq_handler_t thread_fn, unsigned long irqflags,
			 const char *devname, void *dev_id)
{
	struct irqaction *action;
	struct irq_desc *desc;
	int retval;
    ...
    ...
    ...
}
```

该函数开始定义了`irqaction`和`irq_desc`两个变量，在本章我们已经了解这两个结构体了。第一个结构体(`irqaction`)表示中断动作描述符，它包含中断处理程序指针，设备名称，中断号等等。第二个结构体(`irq_desc`)表示中断描述符，包含指向 `irqaction`的指针，中断标志等等。`request_threaded_irq`函数被`request_irq`调用时，带了一个额外的参数：`irq_handler_t thread_fn`。如果这个参数不为`NULL`，它会创建`irq`线程，并在该线程中执行给定的`irq`处理程序。

下一步，我们要做如下检查：

```C
	if (irq == IRQ_NOTCONNECTED)
		return -ENOTCONN;

	if (((irqflags & IRQF_SHARED) && !dev_id) ||
	    (!(irqflags & IRQF_SHARED) && (irqflags & IRQF_COND_SUSPEND)) ||
	    ((irqflags & IRQF_NO_SUSPEND) && (irqflags & IRQF_COND_SUSPEND)))
		return -EINVAL;
```

首先，我们确保`irq`是有效中断后，对中断标记进行检查，包括：共享中断时传入了`dev_id`，`IRQF_COND_SUSPEND`仅对共享中断生效。否则退出函数，返回`-EINVAL`错误。

之后，我们调用[kernel/irq/irqdesc.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/irqdesc.c#L581)文件中定义的`irq_to_desc`函数将给定的`irq`中断号转换成`irq`中断描述符。如果不成功，则退出函数，返回`-EINVAL`错误：

```C
	desc = irq_to_desc(irq);
	if (!desc)
		return -EINVAL;
```

`irq_to_desc`函数检查给定的`irq`中断号是否小于最大中断号，并且返回中断描述符。这里`irq`中断号就是`irq_desc`数组的偏移量：

```C
struct irq_desc *irq_to_desc(unsigned int irq)
{
        return (irq < NR_IRQS) ? irq_desc + irq : NULL;
}
```

接下来，现在来检查描述符的状态，确保我们可以请求中断，失败则返回`-EINVAL`错误。如下

```C
if (!irq_settings_can_request(desc) || WARN_ON(irq_settings_is_per_cpu_devid(desc)))
    return -EINVAL;
```

接着，我们检查给定的中断处理程序(handler)和中断线程(thread_fn)。如果两个都是`NULL`，则返回`-EINVAL`。如果`handler`为空，`thread_fn`不为空时，则把`handler`设为`irq_default_primary_handler`。如下：

```C
	if (!handler) {
		if (!thread_fn)
			return -EINVAL;
		handler = irq_default_primary_handler;
	}
```

下一步，我们调用`kzalloc`函数为`irqaction`分配内存，分配失败时返回；成功分配空间后，这个结构体进行初始化，设置它的中断处理程序，中断标志，设备名称等等：

```C
	action = kzalloc(sizeof(struct irqaction), GFP_KERNEL);
	if (!action)
		return -ENOMEM;

	action->handler = handler;
	action->thread_fn = thread_fn;
	action->flags = irqflags;
	action->name = devname;
	action->dev_id = dev_id;
```

接下来，我们调用`__setup_irq`函数注册`irqaction`。如下：

```C
	retval = irq_chip_pm_get(&desc->irq_data);
	if (retval < 0) {
		kfree(action);
		return retval;
	}

	retval = __setup_irq(irq, desc, action);

	if (retval) {
		irq_chip_pm_put(&desc->irq_data);
		kfree(action->secondary);
		kfree(action);
	}
```

注意，`__setup_irq`函数的调用位于`irq_chip_pm_get`和`irq_chip_pm_put`函数之间。`irq_chip_pm_get`和`irq_chip_pm_put`这对函数在[kernel/irq/chip.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/chip.c#L1557)中实现，用于给IRQ芯片供电/断电。在此期间，调用失败后返回相应的错误码。

### 2.3 创建中断处理线程

`__setup_irq`函数开头是各种检查。首先我们检查给定的中断描述符不为`NULL`，`irqchip`不为`NULL`，以及给定的中断描述符模块拥有者不为`NULL`。接下来我们检查中断是否嵌套在其他中断线程中，如果可以，我们用以`irq_nested_primary_handler`替换`irq_default_priamry_handler`。

下一步，如果给定的中断不是嵌套的，并且`thread_fn`不为空，调用`setup_irq_thread`函数创建一个中断处理线程，如下：

```C
	if (new->thread_fn && !nested) {
		ret = setup_irq_thread(new, irq, false);
		if (ret)
			goto out_mput;
		if (new->secondary) {
			ret = setup_irq_thread(new->secondary, irq, true);
			if (ret)
				goto out_thread;
		}
	}

static int
setup_irq_thread(struct irqaction *new, unsigned int irq, bool secondary)
{
    ...
	if (!secondary) {
		t = kthread_create(irq_thread, new, "irq/%d-%s", irq,
				   new->name);
	} else {
		t = kthread_create(irq_thread, new, "irq/%d-s-%s", irq,
				   new->name);
		param.sched_priority -= 1;
	}
    ...
}
```

此后，根据`flags`标志设置中断描述符的剩余字段。在最后，调用`wake_up_process`函数唤起中断线程；调用`register_irq_proc`函数创建`/proc/irq/<irq>`目录等；调用`register_handler_proc`函数创建`/proc/irq/<irq>/handler/`目录。如下：

```C
	if (new->thread)
		wake_up_process(new->thread);
	if (new->secondary)
		wake_up_process(new->secondary->thread);

	register_irq_proc(irq, desc);
	new->dir = NULL;
	register_handler_proc(irq, new);
```

### 2.4 共享中断执行

在`__setup_irq`函数设置`irq`后，返回`request_threaded_irq`函数。在最后，执行中断函数。如下：

```C
#ifdef CONFIG_DEBUG_SHIRQ_FIXME
	if (!retval && (irqflags & IRQF_SHARED)) {
		unsigned long flags;

		disable_irq(irq);
		local_irq_save(flags);

		handler(irq, dev_id);

		local_irq_restore(flags);
		enable_irq(irq);
	}
#endif
```

在`CONFIG_DEBUG_SHIRQ_FIXME`内核配置选项开启时，如果是共享中断(`IRQF_SHARED`)，调用`handler`执行一次中断。

此时，`16`和`17`号中断请求线注册完毕。当一个中断控制器获得这些中断的相关事件时，`serial21285_rx_chars`和`serial21285_tx_chars`函数会被调用。现在我们来看看中断发生时发生了什么。

## 3 中断处理过程

通过上文，我们分析了为中断描述符请求中断号注册`irqaction`结构体的过程。在本章第八部分，我们分析了`native_init_IRQ` 函数，这个函数会初始化本地APIC。

### 3.1 ISA设置IRQ中断处理函数

在`native_init_IRQ`函数中，我们首先调用`x86_init.irqs.pre_vector_init();`(即：`init_ISA_irqs`)函数设置ISA中断，如下：

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

可以看到，调用`irq_set_chip_and_handler`函数设置传统IRQ的`handle_irq`为`handle_level_irq`。

驱动程序和板卡级别代码可用通过下面几个函数设置IRQ中断处理函数：

* irq_set_handler();
* irq_set_chip_and_handler();
* irq_set_chip_and_handler_name();

Linux内核中内置了不同的IRQ标准流控回调函数，包括：

* handle_level_irq -- 用于电平触发中断的流控处理；
* handle_fasteoi_irq -- 用于需要响应eoi的中断控制器；
* handle_edge_irq -- 用于边沿触发中断的流控处理；
* handle_simple_irq -- 用于简易流控处理；
* handle_percpu_irq -- 用于只在单一cpu响应的中断；
* handle_nested_irq -- 用于处理使用线程的嵌套中断；

### 3.2 IRQ中断处理过程

IRQ中断调用`do_IRQ`函数。`do_IRQ`函数在[arch/x86/kernel/irq.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/irq.c#L233)中实现，如下：

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

`do_IRQ`函数接受一个参数 - `pt_regs`结构体，它存放着用户空间寄存器的值。执行过程可以分成三个部分，进入IRQ、执行IRQ、退出IRQ。

* 进入IRQ的执行过程，包括：`set_irq_regs`(保存当前寄存器)、`entering_irq`(进入IRQ的准备工作，主要是禁用软中断的下半部分)；
* 执行IRQ中断过程包括：根据中断向量获取`irq_desc`中断描述符，调用`generic_handle_irq_desc`函数执行中断，最终调用`desc->handle_irq(desc)`（即：中断描述符中的中断处理函数），或者调用`ack_APIC_irq`函数（默认中断处理程序）；
* 退出IRQ的执行过程，包括：`exiting_irq`(退出IRQ的工作，主要是存在软中断时调用软中断)，`set_irq_regs`(恢复旧寄存器)；

IRQ中断执行时，调用`generic_handle_irq_desc`函数执行中断，如下：

```C
static inline void generic_handle_irq_desc(unsigned int irq, struct irq_desc *desc)
{
       desc->handle_irq(irq, desc);
}
```

由于，我们分析的结构平台为`x86_64`，而`StringARM** SA-100/21285`评估板需要运行在`ARM`平台下。这里我们以`handle_irq`设置为`handle_level_irq`为例。

### 3.3 IRQ中断处理过程

`handle_level_irq`函数在[kernel/irq/chip.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/chip.c#L630)中实现，在进行必要检查后，调用`handle_irq_event`函数，如下：

```C
void handle_level_irq(struct irq_desc *desc)
{
	raw_spin_lock(&desc->lock);
	mask_ack_irq(desc);
	...
	...
	kstat_incr_irqs_this_cpu(desc);
	handle_irq_event(desc);

	cond_unmask_irq(desc);

out_unlock:
	raw_spin_unlock(&desc->lock);
}
```

`handle_irq_event`函数在[kernel/irq/handle.c](https://github.com/torvalds/linux/blob/v5.4/kernel/irq/handle.c#L198)中实现，如下：

```C
irqreturn_t handle_irq_event(struct irq_desc *desc)
{
	irqreturn_t ret;

	desc->istate &= ~IRQS_PENDING;
	irqd_set(&desc->irq_data, IRQD_IRQ_INPROGRESS);
	raw_spin_unlock(&desc->lock);

	ret = handle_irq_event_percpu(desc);

	raw_spin_lock(&desc->lock);
	irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);
	return ret;
}
```

在`handle_irq_event_percpu`函数中调用`__handle_irq_event_percpu`函数处理中断，后者遍历所有的`actions`，逐项调用。如下：

```C
irqreturn_t __handle_irq_event_percpu(struct irq_desc *desc, unsigned int *flags)
{
	irqreturn_t retval = IRQ_NONE;
	unsigned int irq = desc->irq_data.irq;
	struct irqaction *action;

	record_irq_time(desc);

	for_each_action_of_desc(desc, action) {
		irqreturn_t res;

		trace_irq_handler_entry(irq, action);
		res = action->handler(irq, action->dev_id);
		trace_irq_handler_exit(irq, action, res);
		...
		...
        switch (res) {
		case IRQ_WAKE_THREAD:
			...
			__irq_wake_thread(desc, action);
            ...
		}
		retval |= res;
	}

	return retval;
}
```

`action->handler`即我们设置的`serial21285_tx_chars`或者`serial21285_rx_chars`。就这样，当一个中断发生时，`serial21285_tx_chars`或者`serial21285_rx_chars`函数会被调用。

如果，`action->handler`返回值需要开启线程时(即，`IRQ_WAKE_THREAD`)，调用`__irq_wake_thread`函数起中断线程。

### 3.4 IRQ中断线程

在`__setup_irq`函数中，我们调用`setup_irq_thread`函数创建了`irqaction`的中断线程。线程的入口函数为`irq_thread`，实现如下：

```C
static int irq_thread(void *data)
{
	struct callback_head on_exit_work;
	struct irqaction *action = data;
	struct irq_desc *desc = irq_to_desc(action->irq);
	irqreturn_t (*handler_fn)(struct irq_desc *desc,
			struct irqaction *action);

	if (force_irqthreads && test_bit(IRQTF_FORCED_THREAD,
					&action->thread_flags))
		handler_fn = irq_forced_thread_fn;
	else
		handler_fn = irq_thread_fn;

	init_task_work(&on_exit_work, irq_thread_dtor);
	task_work_add(current, &on_exit_work, false);

	irq_thread_check_affinity(desc, action);

	while (!irq_wait_for_interrupt(action)) {
		irqreturn_t action_ret;

		irq_thread_check_affinity(desc, action);

		action_ret = handler_fn(desc, action);
		if (action_ret == IRQ_WAKE_THREAD)
			irq_wake_secondary(desc, action);

		wake_threads_waitq(desc);
	}

	task_work_cancel(current, irq_thread_dtor);
	return 0;
}
```

可以看到，根据线程标记设置`handler_fn`，然后，循环调用`irq_wait_for_interrupt`函数判断是否触发中断，触发时，调用`handler_fn`。

设置的`handler_fn`函数包括`irq_forced_thread_fn`或`irq_thread_fn`两类。`irq_forced_thread_fn`函数执行时，需要关闭中断上下文，执行完成后开启中断上下文。这两者都会调用`action->thread_fn`函数。如下：

```C
	ret = action->thread_fn(action->irq, action->dev_id);
	if (ret == IRQ_HANDLED)
		atomic_inc(&desc->threads_handled);

	irq_finalize_oneshot(desc, action);
```

## 4 结束语

本文是中断和中断处理的最后一部分。本文以`StringARM** SA-100/21285`评估板为例，深入分析了硬件IRQ中断的处理过程。当然，本节甚至本章都未能覆盖到Linux内核中断和中断处理的所有方面。Linux中断及中断处理是一个浩大的工作，这里只是分析了一部分内容。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
