# 内核系统调用 （第一部分）

## 0 介绍

从本节开始将介绍Linux内核中[System Call](https://en.wikipedia.org/wiki/System_call)的概念。在前一章中，我们了解了中断及中断处理。系统调用的概念与中断非常相似，这是因为软件中断是执行系统调用最常见的方式。接下来我们将从不同的角度来分析系统调用相关概念。例如，从用户空间发起系统调用时会发生什么，Linux内核中一组系统调用处理器的实现，[VDSO](https://en.wikipedia.org/wiki/VDSO) 和 [vsyscall](https://lwn.net/Articles/446528/) 的概念以及其他信息。

在了解Linux内核系统调用执行过程之前，让我们先来了解一些系统调用的相关原理。

## 1 什么是系统调用?

### 1.1 初识系统调用

系统调用就是从用户空间发起的内核服务请求。操作系统内核其实会提供很多服务，比如：当程序想要读写文件、监听某个[socket](https://en.wikipedia.org/wiki/Network_socket)端口、删除或创建目录或者程序结束时，都会执行系统调用。换句话说，系统调用其实就是由用户空间程序调用处理某些请求的[C](https://en.wikipedia.org/wiki/C_%28programming_language%29)内核空间函数。

Linux内核提供一系列功能函数，但这些函数与CPU架构相关。 例如：[x86_64](https://en.wikipedia.org/wiki/X86-64)提供[435](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscall_64.tbl)个系统调用，[x86](https://en.wikipedia.org/wiki/X86)提供[547](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscall_32.tbl)个不同的系统调用。系统调用仅仅是一些函数。

我们看一个使用汇编语言编写的简单 `Hello world` 示例:

```C
.data

msg:
    .ascii "Hello, world!\n"
    len = . - msg

.text
    .global _start

_start:
    movq  $1, %rax
    movq  $1, %rdi
    movq  $msg, %rsi
    movq  $len, %rdx
    syscall

    movq  $60, %rax
    xorq  %rdi, %rdi
    syscall
```

使用下面的命令编译后执行:

```bash
$ gcc -c test.S
$ ld -o test test.o
$ ./test
Hello, world!
```

这些代码是Linux`x86_64`架构下`Hello world`的汇编程序，代码包含两段：`.data`和 `.text`。`.data`存储程序的初始数据 (在示例中为`Hello world`字符串)，`.text`包含程序的代码。代码可分为两部分: 第一部分为第一个`syscall`指令之前的代码，第二部分为两个`syscall`指令之间的代码。

### 1.2 系统调用的寄存器设置

在示例程序及一般应用中，`syscall` 指令有什么功能？在[64-ia-32-architectures-software-developer-vol-2b-manual](http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html)中提到:

```tex
SYSCALL可以以优先级0调起系统调用处理程序，它通过加载IA32_LSTAR MSR至RIP完成调用(在RCX中保存 SYSCALL 指令地址之后)。(WRMSR 指令确保IA32_LSTAR MSR总是包含一个连续的地址。)
...
...
...
SYSCALL将IA32_STAR MSR的47:32位加载至CS和SS段选择器。总之，CS和SS描述符缓存不是从段描述符(在 GDT 或者 LDT 中)加载的。

相反，描述符缓存加载固定值。确保从段选择器得到的描述符和从描述符缓冲中得到的固定值保持一致是操作系统的本职工作，但 SYSCALL指令不保证两者的一致。
```

总而言之，`syscall`指令跳转到`MSR_LSTAR`[模型特定寄存器(MSR)](https://en.wikipedia.org/wiki/Model-specific_register)中存储的地址。内核负责提供自定义的函数来处理系统调用，以及在系统启动时将此处理函数的地址写入到`MSR_LSTAR`寄存器中。

`x86_64`架构下这个自定义的函数为`entry_SYSCALL_64`，在[arch/x86/entry/entry_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/entry_64.S#L145)中定义。在[arch/x86/kernel/cpu/common.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/cpu/common.c#L1668)文件中`syscall_init`函数中写入函数地址：

```C
wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
```

因此，`syscall`指令调用指定的系统调用处理程序。但是如何确定调用哪个处理程序？事实上这些信息从[通用寄存器](https://en.wikipedia.org/wiki/Processor_register)得到。正如[系统调用表](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscall_64.tbl)中描述描述的那样，每个系统调用对应特定的编号。

### 1.3 `write`系统调用简介

在我们的示例中, 第一个系统调用是`write`，将数据写入指定文件。在系统调用表中，[write](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscall_64.tbl#L12)系统调用的编号为`1`。在示例中通过`rax`寄存器传递该编号，接下来的几个寄存器: `%rdi`, `%rsi` 和 `%rdx` 分别保存 `write` 系统调用的三个参数。在示例中它们分别是：

* [文件描述符](https://en.wikipedia.org/wiki/File_descriptor) (`1`表示[stdout](https://en.wikipedia.org/wiki/Standard_streams#Standard_output_.28stdout.29))
* 字符串指针
* 数据大小

是的，你没有看错，这就是系统调用的参数。正如上文所示, 系统调用是内核空间的`C`函数。在我们的示例中，第一个系统调用为`write`，在 [fs/read_write.c](https://github.com/torvalds/linux/blob/v5.4/fs/read_write.c#L620)文件中定义,如下:

```C
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	return ksys_write(fd, buf, count);
}
```

或者是:

```C
ssize_t write(unsigned int fd, const char __user *buf, size_t count)
```

暂时不用考虑`SYSCALL_DEFINE3`宏，我们稍后再做讨论。

示例的第二部分也是一样的, 但调用了另一系统调用[exit](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscall_64.tbl#L71)，这个系统调用仅需一个参数 -- 退出值，说明程序退出的方式。

[strace](https://en.wikipedia.org/wiki/Strace)工具可根据程序的名称输出系统调用的过程:

```bash
$ strace ./test
execve("./test", ["./test"], 0x7ffcc59a98b0 /* 34 vars */) = 0
write(1, "Hello, world!\n", 14Hello, world!
)         = 14
exit(0)                                 = ?
+++ exited with 0 +++
```

`strace` 输出的第一行, [execve](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl#L68)系统调用来执行程序，第二、三行为程序中使用的系统调用`write`和`exit`。注意示例中通过通用寄存器传递系统调用的参数，寄存器的顺序是指定的，顺序在[x86-64调用约定](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions)中定义。`x86_64`架构在[System V Application Binary Interface](https://refspecs.linuxbase.org/elf/x86_64-abi-0.21.pdf)中进行声明。通常，函数参数被置于寄存器或者堆栈中，顺序为: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`。这六个寄存器分别对应函数的前六个参数，若函数多于六个参数，其他参数将被放在堆栈中。

我们不会在代码中直接使用系统调用，但当我们想打印某些信息、检测文件权限或是读写数据都会用到系统调用。例如:

```C
#include <stdio.h>

int main(int argc, char **argv)
{
   FILE *fp;
   char buff[255];

   fp = fopen("test.txt", "r");
   fgets(buff, 255, fp);
   printf("%s\n", buff);
   fclose(fp);

   return 0;
}
```

Linux内核中没有`fopen`, `fgets`, `printf`和`fclose`系统调用，而是 `open`, `read` `write` 和 `close`。`fopen`, `fgets`, `printf` 和 `fclose` 仅仅是 `C` [standard library](https://en.wikipedia.org/wiki/GNU_C_Library)中定义的函数。事实上这些函数是系统调用的封装，我们不会在代码中直接使用系统调用，而是使用标准库的[封装](https://en.wikipedia.org/wiki/Wrapper_function)函数。主要原因非常简单: 必须快速、非常快速的执行系统调用，系统调用快的同时也要非常小。标准库会在执行系统调用前，确保系统调用参数设置正确并且完成一些其他不同的检查。我们用以下命令编译下示例程序：

```bash
~$ gcc -no-pie test.c -o test
```

通过[ltrace](https://en.wikipedia.org/wiki/Ltrace)工具检查:

```bash
$ ltrace ./test
fopen("test.txt", "r")                           = 0x8002a0
fgets("hello world!\n", 255, 0x8002a0)           = 0x7ffc3401ee30
puts("hello world!\n"hello world!

)                           = 14
fclose(0x8002a0)                                 = 0
+++ exited (status 0) +++
```

`ltrace`工具显示程序在用户空间的调用，`fopen`函数打开给定的文本文件, `fgets`函数读取文件内容至`buf`缓存,  `puts`输出文件内容至`stdout`, `fclose`函数根据文件描述符关闭函数。如上文描述，这些函数调用特定的系统调用。例如：`puts`内部调用`write` 系统调用，`ltrace` 添加 `-S`可观察到这一调用:

```bash
SYS_write(1, "hello world!\n", 13hello world!
)               = 13
```

系统调用是普遍存在的，每个程序都需要打开、写、读文件，网络连接，内存分配和许多其他功能，这些功能只能由内核提供。[proc](https://en.wikipedia.org/wiki/Procfs)文件系统有一个特殊文件: `/proc/${pid}/syscall`。该文件记录了进程正在调用的系统调用的编号和参数。例如，进程号`1`的程序是[systemd](https://en.wikipedia.org/wiki/Systemd)，如下：

```bash
$ sudo cat /proc/1/comm
systemd

$ sudo cat /proc/1/syscall
232 0x4 0x7ffdf82e11b0 0x1f 0xffffffff 0x100 0x7ffdf82e11bf 0x7ffdf82e11a0 0x7f9114681193
```

编号为`232`的系统调用为[epoll_wait](https://github.com/torvalds/linux/blob/v5.4/arch/x86/entry/syscalls/syscall_64.tbl#L243)，该调用等待[epoll](https://en.wikipedia.org/wiki/Epoll) 文件描述符的I/O事件。

现在我们对系统调用有所了解，知道什么是系统调用及为什么需要系统调用。接下来，讨论示例程序中使用的 `write` 系统调用。

## 2 write系统调用的实现

`write`系统调用在[fs/read_write.c](https://github.com/torvalds/linux/blob/v5.4/fs/read_write.c#L620)文件中实现，如下：

```C
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	return ksys_write(fd, buf, count);
}
```

### 2.1 `write`系统调用的函数定义

首先，`SYSCALL_DEFINE3`宏在[include/linux/syscalls.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/syscalls.h#L216)中定义，扩展为`sys_name(...)`的函数定义，如下:

```C
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)

#define SYSCALL_DEFINEx(x, sname, ...)                \
        SYSCALL_METADATA(sname, x, __VA_ARGS__)       \
        __SYSCALL_DEFINEx(x, sname, __VA_ARGS__)
```

`SYSCALL_DEFINE3`宏的参数中`name`代表系统调用的名称和可变个数的参数。这个宏仅仅为`SYSCALL_DEFINEx`宏的扩展确定了传入宏的参数个数。`_##name`作为未来系统调用名称的存根。让我们来看看`SYSCALL_DEFINEx`这个宏，这个宏扩展为以下两个宏:

* `SYSCALL_METADATA`;
* `__SYSCALL_DEFINEx`.

第一个宏 `SYSCALL_METADATA`的实现依赖于`CONFIG_FTRACE_SYSCALLS`内核配置选项。从选项的名称可以知道，它允许tracer捕获系统调用的进入和退出。若该内核配置选项开启，`SYSCALL_METADATA`宏初始化[include/trace/syscall.h](https://github.com/torvalds/linux/blob/v5.4/include/trace/syscall.h#L25)中的`syscall_metadata`结构，该结构中包含：系统调用的名称, 系统调用编号、参数个数、参数类型列表等:

```C
#define SYSCALL_METADATA(sname, nb, ...)                             \
	...                                                              \
	...                                                              \
	...                                                              \
	static struct syscall_metadata __used			\
	  __syscall_meta_##sname = {				\
		.name 		= "sys"#sname,			\
		.syscall_nr	= -1,	/* Filled in at boot */	\
		.nb_args 	= nb,				\
		.types		= nb ? types_##sname : NULL,	\
		.args		= nb ? args_##sname : NULL,	\
		.enter_event	= &event_enter_##sname,		\
		.exit_event	= &event_exit_##sname,		\
		.enter_fields	= LIST_HEAD_INIT(__syscall_meta_##sname.enter_fields), \
	};							\
	static struct syscall_metadata __used			\
	  __attribute__((section("__syscalls_metadata")))	\
	 *__p_syscall_meta_##sname = &__syscall_meta_##sname;
```

若`CONFIG_FTRACE_SYSCALLS`内核配置未开启时，此时`SYSCALL_METADATA`扩展为空字符串:

```C
#define SYSCALL_METADATA(sname, nb, ...)
```

第二个宏`__SYSCALL_DEFINEx`在`x86_64`下，在[arch/x86/include/asm/syscall_wrapper.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/asm/syscall_wrapper.h#L157)中定义，如下:

```C
#define __SYSCALL_DEFINEx(x, name, ...)					\
	asmlinkage long __x64_sys##name(const struct pt_regs *regs);	\
	ALLOW_ERROR_INJECTION(__x64_sys##name, ERRNO);			\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __x64_sys##name(const struct pt_regs *regs)	\
	{								\
		return __se_sys##name(SC_X86_64_REGS_TO_ARGS(x,__VA_ARGS__));\
	}								\
	__IA32_SYS_STUBx(x, name, __VA_ARGS__)				\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
```

第一个函数`sys##name`是用给定的名称来定义系统调用函数。 宏`__SC_DECL`的参数包括`__VA_ARGS__`、传入参数系统类型和参数名称，因为宏定义中无法指定参数类型。`__MAP`宏用于宏`__SC_DECL`给`__VA_ARGS__`参数。其他的函数是`__SYSCALL_DEFINEx`生成的，详细信息可以查阅[CVE-2009-0029](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0029)，此处不再深究。总之，`write`的系统调用函数定义如下:

```C
asmlinkage long sys_write(unsigned int fd, const char __user * buf, size_t count);
```

### 2.2 `write`系统调用的实现过程

现在我们对系统调用的定义有一定了解，再来回头看看`write`系统调用的实现:

```C
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	return ksys_write(fd, buf, count);
}
```

该调用的功能是将用户定义的缓冲中的数据写入指定的设备或文件。从代码可知，该调用有三个参数:

* `fd` - 文件描述符；
* `buf` - 写入的缓冲区；
* `count` - 写入缓冲区大小；

注意第二个参数`buf`, 定义了`__user`属性。该属性的主要目的是通过[sparse](https://en.wikipedia.org/wiki/Sparse)工具检查Linux内核代码。`__user`定义于[include/linux/compiler_types.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/compiler_types.h#L8)头文件中，并依赖Linux内核中`__CHECKER__`的定义。以上全是关于 `sys_write`系统调用的有用元信息。

我们可以看到，它只是调用了`ksys_write`函数，并传递了相同的参数。如下：

```C
ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_write(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}

	return ret;
}
```

`ksys_write`函数实现开始于`f`结构的定义，`f`是`struct fd`类型，`fd`结构是Linux内核中的文件描述符，也是我们存放 `fdget_pos`函数调用结果的地方。`fdget_pos`函数在[include/linux/file.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/file.h#L70)中定义，只是扩展了`__to_fd`函数的扩展:

```C
static inline struct fd fdget_pos(int fd)
{
        return __to_fd(__fdget_pos(fd));
}
```

`fdget_pos`函数将给定数字的文件描述符转化为`fd`结构。通过一系列函数调用后，`fdget_pos`函数得到当前进程的文件描述符表(`current->files`), 并尝试从表中获取一致的文件描述符编号。当获取到给定文件描述符的`fd`结构后, 检查文件并返回文件是否存在。

通过调用函数`file_pos_read`获取当前处于文件中的位置，返回文件的`f_pos`字段，如下:

```C
static inline loff_t *file_ppos(struct file *file)
{
	return file->f_mode & FMODE_STREAM ? NULL : &file->f_pos;
}
```

接下来再调用 `vfs_write`函数, `vfs_write`函数在[fs/read_write.c](https://github.com/torvalds/linux/blob/v5.4/fs/read_write.c#L542)中实现，向指定文件的指定位置写入指定缓冲中的数据。此处不深入`vfs_write` 函数的细节，因为这个函数与`系统调用`没有太多联系，与[虚拟文件系统](https://en.wikipedia.org/wiki/Virtual_file_system)相关。

`vfs_write` 结束相关工作后，改变在文件中的位置:

```C
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
```

在`write`系统调用处理函数的最后, 我们可以看到以下函数调用:

```C
fdput_pos(f);
```

该函数进行清理，如：解锁文件描述符中的并行处理的互斥量`f_pos_lock`。

我们讨论了Linux内核提供的系统调用的部分实现。显然略过了`write`系统调用实现的部分内容，正如文中所述, 在该章节中仅关心系统调用的相关内容，不讨论与其他子系统相关的内容，例如[虚拟文件系统](https://en.wikipedia.org/wiki/Virtual_file_system).

## 3 结束语
  
本文介绍了Linux内核中的系统调用概念。以`write`为例，介绍了系统调用的理论，在下一部分中，我们将继续深入这个主题，讨论与系统调用相关的Linux内核代码。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
