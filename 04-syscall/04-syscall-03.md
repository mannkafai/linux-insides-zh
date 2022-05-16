# 内核系统调用 （第三部分）

## 0 vsyscalls和vDSO

在上一节中分析了用户空间应用程序发起的系统调用的准备工作及系统调用的处理过程。在这一节将讨论两个与系统调用十分相似的概念，这两个概念是`vsyscall`和`vdso`。

系统调用是Linux内核一种特殊的运行机制，使得用户空间的应用程序可以请求特权级下的任务（例如：读取或写入文件、打开套接字等）。正如你所了解的，在Linux内核中发起一个系统调用是特别昂贵的操作，因为处理器必须中断当前正在执行的任务，切换内核模式的上下文，在系统调用处理完毕后跳转至用户空间。`vsyscall`和`vdso`两种机制被设计用来加速系统调用的处理，在这一节我们将了解两种机制的工作原理。

## 1 vsyscalls

### 1.1 vsyscalls介绍

`vsyscall`或`virtual system call`是第一种也是最古老的一种用于加快系统调用的机制。`vsyscall`的工作原则其实十分简单，Linux内核在用户空间映射一个包含一些变量及一些系统调用的实现的内存页。对于[X86_64](https://en.wikipedia.org/wiki/X86-64)架构可以在Linux内核的[文档](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/x86_64/mm.rst)找到关于这一内存区域的信息：

```text
 ffffffffff600000 |  -10    MB | ffffffffff600fff |    4 kB | legacy vsyscall ABI
```

或者：

```bash
~$ sudo cat /proc/1/maps | grep vsyscall
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

因此，这些系统调用将在用户空间下执行，这意味着将不发生[上下文切换](https://en.wikipedia.org/wiki/Context_switch)。

### 1.2 vsyscalls初始化

`vsyscall`内存页的映射在[arch/x86/entry/vsyscall/vsyscall_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/vsyscall/vsyscall_64.c#L376)中定义的 `map_vsyscall`函数中实现。这一函数在Linux内核初始化时在[arch/x86/kernel/setup.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/setup.c#L837)文件中的`setup_arch`函数中调用。

`map_vsyscall`函数的实现依赖于`CONFIG_X86_VSYSCALL_EMULATION`的内核配置选项:

```C
#ifdef CONFIG_X86_VSYSCALL_EMULATION
extern void map_vsyscall(void);
#else
static inline void map_vsyscall(void) {}
#endif
```

正如帮助文档中所描述的，`CONFIG_X86_VSYSCALL_EMULATION`配置选项：`使能 vsyscall 模拟`。为何模拟`vsyscall`？事实上，`vsyscall`由于安全原因是一种遗留 [ABI](https://en.wikipedia.org/wiki/Application_binary_interface)。虚拟系统调用具有固定的地址，在[System.map]意味着`vsyscall`内存页的位置在任何时刻是相同，这个位置是在`map_vsyscall`函数中指定的。如下：

```C
void __init map_vsyscall(void)
{
    extern char __vsyscall_page;
    unsigned long physaddr_vsyscall = __pa_symbol(&__vsyscall_page);
	...
	...
	...
}
```

在`map_vsyscall`函数的开始，通过`__pa_symbol`宏获取`vsyscall`内存页的物理地址。`__vsyscall_page`在[arch/x86/entry/vsyscall/vsyscall_emu_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/vsyscall/vsyscall_emu_64.S#L18)文件中定义，具有如下的[虚拟地址](https://en.wikipedia.org/wiki/Virtual_address_space):

```bash
$ sudo cat /proc/kallsyms | grep __vsyscall_page
ffffffff82604000 D __vsyscall_page
```

`__vsyscall_page`的定义如下：

```text
__PAGE_ALIGNED_DATA
	.globl __vsyscall_page
	.balign PAGE_SIZE, 0xcc
	.type __vsyscall_page, @object
```

`__PAGE_ALIGNED_DATA`在[include/linux/linkage.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/linkage.h#L48)中定义，如下：

```C
#define __PAGE_ALIGNED_DATA	.section ".data..page_aligned", "aw"
```

表示`__vsyscall_page`在`.data..page_aligned, aw`[段](https://en.wikipedia.org/wiki/Memory_segmentation)中。

`__vsyscall_page`包含三个系统调用：`gettimeofday`, `time` 和 `getcpu`。如下：

```C
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
```

回到`map_vsyscall`函数，在得到`__vsyscall_page`物理地址之后，根据`vsyscall_mode`进行不同的设置。`vsyscall_mode`变量可以在早期命令行参数解析时通过`vsyscall_setup`函数来获取：

```C
static int __init vsyscall_setup(char *str)
{
	if (str) {
		if (!strcmp("emulate", str))
			vsyscall_mode = EMULATE;
		else if (!strcmp("xonly", str))
			vsyscall_mode = XONLY;
		else if (!strcmp("none", str))
			vsyscall_mode = NONE;
		else
			return -EINVAL;

		return 0;
	}

	return -EINVAL;
}
early_param("vsyscall", vsyscall_setup);
```

* 全模拟模式

如果`vsyscall_mode == EMULATE`，此时`vsyscall`为全模拟模式，需要将页表映射到内存中。实现过程如下：调用`__set_fixmap`函数将`VSYSCALL_PAGE`映射到`__vsyscall_page`的物理页上，调用`set_vsyscall_pgtable_user_bits`函数设置`VSYSCALL_PAGE`页可以通过用户模式访问，如下：

```C
	if (vsyscall_mode == EMULATE) {
		__set_fixmap(VSYSCALL_PAGE, physaddr_vsyscall,
			     PAGE_KERNEL_VVAR);
		set_vsyscall_pgtable_user_bits(swapper_pg_dir);
	}
```

`VSYSCALL_PAGE`在[arch/x86/include/asm/fixmap.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/fixmap.h#L80)中定义；`VSYSCALL_ADDR`在[arch/x86/include/uapi/asm/vsyscall.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/uapi/asm/vsyscall.h#L11)中定义，如下：

```C
enum fixed_addresses {
...
...
#ifdef CONFIG_X86_VSYSCALL_EMULATION
	VSYSCALL_PAGE = (FIXADDR_TOP - VSYSCALL_ADDR) >> PAGE_SHIFT,
#endif
...
...
};
#define FIXADDR_TOP	(round_up(VSYSCALL_ADDR + PAGE_SIZE, 1<<PMD_SHIFT) - \
			 PAGE_SIZE)
...
...
#define VSYSCALL_ADDR (-10UL << 20)
```

可以看到，`VSYSCALL_PAGE`值为`511`。`PAGE_KERNEL_VVAR`表示内存页的标志位，在[arch/x86/include/asm/pgtable_types.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/pgtable_types.h#L209)文件中定义，如下：

```C
#define __PAGE_KERNEL_VVAR		(__PAGE_KERNEL_RO | _PAGE_USER)
#define PAGE_KERNEL_VVAR	default_pgprot(__PAGE_KERNEL_VVAR | _PAGE_ENC)
```

标志中带有`_PAGE_USER`标志，这意味着内存页可被用户模式进程访问。

* 只执行模式

如果`vsyscall_mode == XONLY`，此时`vsyscall`为只执行模式，通过`gate_vma`内存区域来实现。实现过程如下：

```C
	if (vsyscall_mode == XONLY)
		gate_vma.vm_flags = VM_EXEC;
```

`gate_vma`在同一个文件中定义，如下：

```C
static struct vm_area_struct gate_vma __ro_after_init = {
	.vm_start	= VSYSCALL_ADDR,
	.vm_end		= VSYSCALL_ADDR + PAGE_SIZE,
	.vm_page_prot	= PAGE_READONLY_EXEC,
	.vm_flags	= VM_READ | VM_EXEC,
	.vm_ops		= &gate_vma_ops,
};
```

可以看到`gate_vma`内存区域的开始地址为`VSYSCALL_ADDR`，结束地址为`VSYSCALL_ADDR + PAGE_SIZE`。

在函数 `vsyscall_map`的最后通过`BUILD_BUG_ON`宏检查`vsyscall`内存页的虚拟地址是否等于变量 `VSYSCALL_ADDR`：

```C
BUILD_BUG_ON((unsigned long)__fix_to_virt(VSYSCALL_PAGE) !=
		     (unsigned long)VSYSCALL_ADDR);
```

就这样`vsyscall`内存页设置完毕。

### 1.3 vsyscalls调用过程

在执行虚拟系统调用处理程序将导致[页面错误]((https://en.wikipedia.org/wiki/Page_fault))异常。`vsyscall`内存页具有`__PAGE_KERNEL_VVAR`的访问权限，这个页将禁止执行。`#PF`页面异常处理函数`do_page_fault`中，判断缺页地址为虚拟系统调用时，调用`emulate_vsyscall`函数。如下：

```C
#ifdef CONFIG_X86_64
	if (is_vsyscall_vaddr(address)) {
		if (emulate_vsyscall(hw_error_code, regs, address))
			return;
	}
#endif
```

`emulate_vsyscall`函数在[arch/x86/entry/vsyscall/vsyscall_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/vsyscall/vsyscall_64.c#L120)中定义，如下：

```C
bool emulate_vsyscall(unsigned long error_code,
		      struct pt_regs *regs, unsigned long address)
{
	...
}
```

`emulate_vsyscall`函数获取虚拟系统调用号、检查是否出错、出现错误时打印错误信息并发送[段错误](https://en.wikipedia.org/wiki/Segmentation_fault)信号。如下：

```C
	...
	...
	vsyscall_nr = addr_to_vsyscall_nr(address);
	trace_emulate_vsyscall(vsyscall_nr);
	if (vsyscall_nr < 0) {
		warn_bad_vsyscall(KERN_WARNING, regs,
				  "misaligned vsyscall (exploit attempt or buggy program) -- look up the vsyscall kernel parameter if you need a workaround");
		goto sigsegv;
	}
	...
	...
sigsegv:
	force_sig(SIGSEGV);
	return true;
```

在检查是虚拟系统调用号时，会进行一些其他检查（例如：是否访问违例），并执行系统调用函数，具体取决于虚拟系统调用：

```C
	switch (vsyscall_nr) {
	case 0:
		if (!write_ok_or_segv(regs->di, sizeof(struct timeval)) ||
		    !write_ok_or_segv(regs->si, sizeof(struct timezone))) {
			ret = -EFAULT;
			goto check_fault;
		}
		syscall_nr = __NR_gettimeofday;
		break;
		...
		...
	}

	ret = -EFAULT;
	switch (vsyscall_nr) {
	case 0:
		ret = __x64_sys_gettimeofday(regs);
		break;
		...
		...
	}
```

在`emulate_vsyscall`函数最后，我们将`__x64_sys_gettimeofday`或另一个系统调用处理结果放入`ax`寄存器，就像正常系统调用所做的那样，恢复[指令指针寄存器](https://en.wikipedia.org/wiki/Program_counter)并将8字节添加到[堆栈指针](https://en.wikipedia.org/wiki/Stack_register)寄存器，此操作模拟`ret`指令。如下：

```C
	regs->ax = ret;

do_ret:
	regs->ip = caller;
	regs->sp += 8;
	return true;

```

## 2 vDSO

### 2.1 vDSO介绍

正如上面描述的那样，`vsyscall`是一个过时的概念，现在由`vDSO`(virtual dynamic shared object)取代。`vsyscall`和`vDSO`的主要区别在于`vDSO`内存页以[共享对象](https://en.wikipedia.org/wiki/Library_%28computing%29#Shared_libraries)的形式映射到每个进程中，但是`vsyscall`在内存中静态的，并且每次都具有相同的地址。对于`x86_64`结构，它被称为`linux-vdso.so.1`，所有用户空间程序通过`glibc`链接到这个动态链接库。例如：

```bash
~$ ldd /bin/uname 
	linux-vdso.so.1 (0x00007ffe70b2d000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f91f8882000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f91f8a90000)
```

或者：

```bash
~$ sudo cat /proc/1/maps | grep vdso
7ffebc5be000-7ffebc5bf000 r-xp 00000000 00:00 0                          [vdso]
```

在这里我们可以看到[uname](https://en.wikipedia.org/wiki/Uname)链接三个库链接：`linux-vdso.so.1`、`libc.so.6` 和 `ld-linux-x86-64.so.2`。第一个提供`vDSO`功能，第二个是`C`[标准库](https://en.wikipedia.org/wiki/C_standard_library)，第三个是程序解释器。因此，`vDSO`在提供类似`vsyscall`功能的同时，解决了`vsyscall`的限制条件。

### 2.2 vDSO初始化

`vDSO`在[arch/x86/entry/vdso/vma.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/vdso/vma.c#L330)文件中的`init_vdso`函数中初始化。该函数根据`CONFIG_X86_X32_ABI`内核配置选项初始化32位和64位`vDSO`镜像，如下：

```C
static int __init init_vdso(void)
{
	init_vdso_image(&vdso_image_64);

#ifdef CONFIG_X86_X32_ABI
	init_vdso_image(&vdso_image_x32);
#endif

	return 0;
}	
```

两个函数都初始化`vdso_image`结构，`vdso_image_x32`和`vdso_image_64`分别在`arch/x86/entry/vdso/vdso-image-x32.c`和`arch/x86/entry/vdso/vdso-image-64.c`文件中定义。这些由[arch/x86/entry/vdso/vdso2c.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/vdso/vdso2c.c#L201)程序从不同的源代码文件中生成的，代表系统调用的不同方法，如：`int 0x80`, `sysenter`等。完整的镜像文件取决于内核配置。以Linux`x86_64`内核，它将包含`vdso_image_64`；`x86`内核包含`vdso_image_x32`；如果内核配置为`x86`架构或`x86_64`兼容模式，使用`vdso_image_32`。如下：

```C
#ifdef CONFIG_X86_64
extern const struct vdso_image vdso_image_64;
#endif

#ifdef CONFIG_X86_X32
extern const struct vdso_image vdso_image_x32;
#endif

#if defined CONFIG_X86_32 || defined CONFIG_COMPAT
extern const struct vdso_image vdso_image_32;
#endif
```

从`vdso_image`结构的名称我们可以认为，它代表了`vDSO`系统调用入口的某种模式的镜像。该结构包括`vDSO`区域大小的信息（大小始终是`PAGE_SIZE`的倍数）、指向文本镜像的指针、开始地址、结束地址等。以`vdso_image_64`结构为例：

```C
const struct vdso_image vdso_image_64 = {
	.data = raw_data,
	.size = 4096,
	.alt = 2501,
	.alt_len = 91,
	.sym_vvar_start = -12288,
	.sym_vvar_page = -12288,
	.sym_pvclock_page = -8192,
	.sym_hvclock_page = -4096,
};
```

`raw_data`包含系统调用的原始二进制代码，为一个页大小（即：4096字节）。

`init_vdso_image`函数在同一个文件中实现，调用`apply_alternatives`函数对镜像指令进行本地替换。如下：

```C
void __init init_vdso_image(const struct vdso_image *image)
{
	BUG_ON(image->size % PAGE_SIZE != 0); 

	apply_alternatives((struct alt_instr *)(image->data + image->alt),
			   (struct alt_instr *)(image->data + image->alt +
						image->alt_len));
}
```

`init_vdso`函数通过`subsys_initcall`宏添加到`initcalls`列表中。列表中的所有函数都将在[init/main.c](https://github.com/torvalds/linux/blob/v5.4/init/main.c#L1009)文件中的`do_initcalls`函数中调用。

```C
subsys_initcall(init_vdso);
```

我们刚刚看到了`vDSO`的初始化和包含`vDSO`系统调用内存页的初始化。但是，他们的页面映射到哪呢？当内核将二进制文件加载到内存时，它们是由内核映射的。Linux内核从[arch/x86/entry/vdso/vma.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/vdso/vma.c#L289)文件中的`arch_setup_additional_pages`函数进行映射，该函数检查`x86_64`下是否启用`vDSO`，并调用`map_vdso_randomized`函数：

```C
int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	if (!vdso64_enabled)
		return 0;

	return map_vdso_randomized(&vdso_image_64);
}
```

`map_vdso_randomized`函数在同一个文件中定义，在调用`vdso_addr`获取`vDSO`映射的随机地址后，调用`map_vdso`函数映射`vDSO`共享变量。`vsyscal`和`vDSO`主要区别在于`vsyscal`使用固定`ffffffffff600000`这个固定地址，并实现3个系统调用；而`vDSO`动态加载并实现5个系统调用，包括：

* `__vdso_clock_gettime`;
* `__vdso_getcpu`;
* `__vdso_gettimeofday`;
* `__vdso_time`；
* `__vdso_clock_getres`;

## 3 结束语

在前面的部分，我们讨论了Linux内核实现系统调用前的准备、退出等实现过程。在这部分中，我们继续深入研究与系统调用概念相关的内容，学习了两个与系统调用非常相似的概念`vsyscall`和`vDSO`。

在所有这三个部分后，我们几乎了解了所有与系统调用相关的事情，包括：什么是系统调用、为什么用户引用程序需要它们、用户引用程序调用系统调用时会发生什么以及内核如何处理系统调用。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
