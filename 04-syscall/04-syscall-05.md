# 内核系统调用 （第五部分）

## 0 介绍

在本章之前的内容部分概述了系统调用的实现机制，现在我们将试着详细讲解Linux内核中不同系统调用的实现。本章之前的部分和本书其他章节描述的Linux内核机制大部分对用户空间是隐约可见或完全不可见。但是Linux内核代码不仅仅是有关内核的，大量的内核代码为我们的应用代码提供了支持。通过Linux内核，我们的程序可以在不知道扇区、磁道和磁盘的其他结构的情况下对文件进行读写操作，我们也不需要手动去构造和封装网络数据包就可以通过网络发送数据。

我们的程序通过[系统调用](https://en.wikipedia.org/wiki/System_call)这个特定的机制和内核进行交互。因此，我决定去写一些系统调用的实现及其行为，比如我们每天会用到的 `read`, `write`, `open`, `close`, `dup` 等等。

我决定从[open](http://man7.org/linux/man-pages/man2/open.2.html)系统调用开始。如果你对`C`程序有了解，你应该知道在我们能对一个文件进行读写或执行其他操作前，我们需要使用 `open` 函数打开这个文件：

```C
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char *argv) {
        int fd = open("test", O_RDONLY);

        if fd < 0 {
                perror("Opening of the file is failed\n");
        }
        else {
                printf("file sucessfully opened\n");
        }

        close(fd); 
        return 0;
}
```

在这样的情况下，`open` 仅是来自标准库中的函数，而不是系统调用。标准库将为我们调用相关的系统调用。`open`调用将返回一个[文件描述符](https://en.wikipedia.org/wiki/File_descriptor)，这个文件描述符是一个独一无二的数值，和被打开的文件息息相关。现在我们使用`open`调用打开了一个文件并且得到了文件描述符，我们可以和这个文件交互了。我们可以写入，读取等等操作。程序中已打开的文件列表可通过[proc](https://en.wikipedia.org/wiki/Procfs) 文件系统获取：

```bash
$ sudo ls /proc/1/fd/
0   13	2   27	31  36	40  45	50  55	6   64	69  73	78  82	87  91	98
1   14	20  28	32  37	41  46	51  56	60  65	7   74	79  83	88  92	99
10  15	22  29	33  38	42  47	52  57	61  66	70  75	8   84	89  93
11  16	23  3	34  39	43  48	53  58	62  67	71  76	80  85	9   94
12  19	26  30	35  4	44  5	54  59	63  68	72  77	81  86	90  95
```

我并不打算在这篇文章中以用户空间的视角来描述`open`函数的细节，会更多地从内核的角度来分析。如果你不是很熟悉`open`函数，你可以在 [man 手册](http://man7.org/linux/man-pages/man2/open.2.html)获取更多信息。

## 1 `open`系统调用的定义

如果你阅读过上一节，你应该知道系统调用通过`SYSCALL_DEFINE`宏定义实现。`open`系统调用位于[fs/open.c](https://github.com/torvalds/linux/blob/v5.4/fs/open.c#L1110)源文件中，如下：

```C
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	if (force_o_largefile())
		flags |= O_LARGEFILE;

	return do_sys_open(AT_FDCWD, filename, flags, mode);
}
```

可以看到，该函数调用了同一个源文件中的`do_sys_open`函数。但是在这个函数被调用前，我们来看看`open`系统调用定义的实现代码中 `if` 分支语句

```C
if (force_o_largefile())
	flags |= O_LARGEFILE;
```

这里可以看到如果`force_o_largefile()`返回true，传递给`open`系统调用的`flags`参数会加上了 `O_LARGEFILE` 标志。`O_LARGEFILE`是什么？阅读`open(2)`[man 手册](http://man7.org/linux/man-pages/man2/open.2.html)可以了解到：

```text
       O_LARGEFILE
              (LFS) Allow files whose sizes cannot be represented in an  off_t
              (but  can  be  represented  in  an  off64_t)  to be opened.  The
              _LARGEFILE64_SOURCE macro must be defined (before including  any
              header  files)  in order to obtain this definition.  Setting the
              _FILE_OFFSET_BITS feature test macro to 64  (rather  than  using
              O_LARGEFILE) is the preferred method of accessing large files on
              32-bit systems (see feature_test_macros(7)).
```

在[GNU C 标准库参考手册](https://www.gnu.org/software/libc/manual/html_mono/libc.html#File-Position-Primitive)中可以获取更多信息：

> Data Type: off_t
> This is a signed integer type used to represent file sizes. In the GNU C Library, this type is no narrower than int.
> If the source is compiled with _FILE_OFFSET_BITS == 64 this type is transparently replaced by off64_t.
>
> Data Type: off64_t
> This type is used similar to off_t. The difference is that even on 32 bit machines, where the off_t type would have 32 bits, off64_t has 64 bits and so is able to address files up to 2^63 bytes in length.
> When compiling with _FILE_OFFSET_BITS == 64 this type is available under the name off_t.

因此不难猜到`off_t`, `off64_t`和 `O_LARGEFILE`是关于文件大小的。就Linux内核而言，在32位系统中如果调用者没有指定 `O_LARGEFILE`标志，就不允许打开大文件。在64位系统上，需要强制加上了这个标志。`force_o_largefile`宏在[include/linux/fcntl.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/fcntl.h#L15)头文件中定义，如下：

```C
#ifndef force_o_largefile
#define force_o_largefile() (!IS_ENABLED(CONFIG_ARCH_32BIT_OFF_T))
#endif
```

因此，`force_o_largefile`在我们当前的[x86_64](https://en.wikipedia.org/wiki/X86-64)架构下展开为`true`，因此`O_LARGEFILE`标志将被添加到 `open`系统调用的`flags`参数中。

现在我们了解`O_LARGEFILE`标志和`force_o_largefile`宏的意义，我们可以继续讨论`do_sys_open`函数的实现，该函数在同一个文件实现，如下：

```C
long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	struct open_flags op;
	int fd = build_open_flags(flags, mode, &op);
	struct filename *tmp;

	if (fd)
		return fd;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fsnotify_open(f);
			fd_install(fd, f);
			trace_do_sys_open(tmp->name, flags, mode);
		}
	}
	putname(tmp);
	return fd;
}
```

让我们试着一步一步理解 `do_sys_open`是如何工作。

## 2 `open`的flags参数

根据函数定义，我们可以知道`open`系统调用的第二个参数`flags`控制文件打开的方式，第三个参数`mode`规定文件的权限。`do_sys_open`函数首先调用`build_open_flags`函数来检查给定的`flags`参数是否有效，并处理不同的`flags`和`mode`条件。

`build_open_flags`函数同样在[fs/open.c](https://github.com/torvalds/linux/blob/v5.4/fs/open.c#L958)中实现，需要三个参数：`flags` -- 控制打开文件的方式；`mode` -- 打开文件的权限；`op` -- `open_flags`结构体。

`open_flags`结构体在[fs/internal.h](https://github.com/torvalds/linux/blob/v5.4/fs/internal.h#L116)文件中定义，该结构体保存了`flags`和权限模式信息。如下：

```C
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};
```

`build_open_flags`函数的主要目的就是生成一个`open_flags`结构体实例。

### 2.1 确定初始访问模式

首先，定义了一个局部变量：

```C
int acc_mode = ACC_MODE(flags);
```

这个局部变量表示访问模式，它的初始值会等于 `ACC_MODE` 宏展开的值，这个宏在[include/linux/fs.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/fs.h#L3510)中定义，如下：

```C
#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
```

`"\004\002\006\006"` 是一个四字符的数组，如下：

```C
"\004\002\006\006" == {'\004', '\002', '\006', '\006'}
```

因此，`ACC_MODE`宏展开后就是数组中`[(x) & O_ACCMODE]`索引的值。我们可以看到，`O_ACCMODE`的值为`00000003`。通过`x & O_ACCMODE`后，我们获取最后两个bit位的值，分别表示 `read`, `write` 和 `read/weite` 访问模式。如下：

```C
#define O_ACCMODE	00000003
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
```

再从数组中计算索引得到值后，`ACC_MODE` 会展开一个文件的访问模式，包含 `MAY_WRITE`, `MAY_READ`和其他信息。

### 2.2 确定文件模式

在我们计算得到初始访问模式后，我们会看到以下条件判断语句：

```C
if (flags & (O_CREAT | __O_TMPFILE))
	op->mode = (mode & S_IALLUGO) | S_IFREG;
else
	op->mode = 0;
```

如果打开文件时，不是新建文件或者临时文件，我们忽略mode，其他情况下传递。这是因为：

> This argument must be supplied when O_CREAT or O_TMPFILE is specified in flags;
> if  neither  O_CREAT nor O_TMPFILE is specified, then mode is ignored

### 2.3 设置打开标记

* 确保不会泄漏文件描述符

在接下来的步骤，我们检查一个文件是否被[fanotify](http://man7.org/linux/man-pages/man7/fanotify.7.html)打开过并且没有`O_CLOSEXEC`标志，来确保不会在用户空间泄漏文件描述符。如下：

```C
flags &= ~FMODE_NONOTIFY & ~O_CLOEXEC;
```

通过`execve`系统调用，新的文件描述符默认设置为保持打开状态，但`open`系统调用支持`O_CLOSEXEC`标志，这样可以被用来改变默认的操作行为。这样即使在一个线程中打开文件并设置`O_CLOSEXEC`标志，同时第二个程序中进行[fork](https://en.wikipedia.org/wiki/Fork_\(system_call\)) + [execve](https://en.wikipedia.org/wiki/Exec_\(system_call\))操作时不会泄露文件描述符。你应该还记得子程序会有一份父程序文件描述符的副本。

* 检查同步标志

接下来检查`flags`参数是否包含`__O_SYNC` 标志，如果包含，则外加`O_DSYNC`标志：

```C
if (flags & __O_SYNC)
	flags |= O_DSYNC;
```

`O_SYNC`标志确保在所有的数据写入到磁盘前，任何关于写的调用不会返回。`O_DSYNC`和`O_SYNC`类似，但`O_DSYNC`不要求等待写入的元数据（如：`atime`, `mtime`等）。

* 检查临时文件标志

接下来，检查是否创建临时文件，用户在创建一个临时文件，必须确认`flags`参数应该包含`O_TMPFILE_MASK`，并且确保文件可写。

```C
if (flags & __O_TMPFILE) {
	if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
		return -EINVAL;
	if (!(acc_mode & MAY_WRITE))
		return -EINVAL;
}
```

因为在 man 手册中有提及：

> O_TMPFILE  must  be  specified  with one of O_RDWR or O_WRONLY

* 检查文件路径标志

检查是否存在文件路径标志，如下：

```C
   else if (flags & O_PATH) {
       	flags &= O_DIRECTORY | O_NOFOLLOW | O_PATH;
        acc_mode = 0;
    }
```

`O_PATH`标志允许我们通过在文件系统目录树中的位置获取文件描述符，只允许在文件描述符层面执行操作。在这种情况下文件自身是没有被打开的，只能使用`dup`, `fcntl` 等操作。因此，使用所有与文件内容相关的操作，像 `read`, `write` 等，就必须使用 `O_DIRECTORY | O_NOFOLLOW | O_PATH` 标志。

现在我们已经分析完成了这些标志，将其设置到`open_flags`：

```C
op->open_flag = flags;
```

### 2.4 设置访问模式

我们在函数的开始获取了初始的访问模式，现在根据标记修改访问模式，如下：

```C
	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;

	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;
```

`O_TRUNC`标志表示将文件长度删减到0，`O_APPEND`标志允许以追加模式打开文件。

### 2.5 确定实际操作

`open_flags`中接下来的设置的字段是`intent`，确定我们真正的操作。换句话说就是我们真正想对文件做什么，打开，新建，重命名等等操作。如果`flags`参数包含`O_PATH`标志，即我们不能对文件内容做任何事情，`intent`设置为`0`，否则设置为`LOOKUP_OPEN`。如果需要新建文件，设置`LOOKUP_CREATE`，`O_EXEC`标志确认文件之前不存在。如下：

```C
	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
		op->intent |= LOOKUP_CREATE;
		if (flags & O_EXCL)
			op->intent |= LOOKUP_EXCL;
	}
```

### 2.6 确定查找操作

`open_flags`结构体里最后的标志是`lookup_flags`，确定路径查找方式。如下：

```C
	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	op->lookup_flags = lookup_flags;
```

`O_DIRECTORY`表示目录，我们使用`LOOKUP_DIRECTORY`；如果想要遍历但不使用[软链接](https://en.wikipedia.org/wiki/Symbolic_link)，使用`LOOKUP_FOLLOW`。

## 3 `open`的实际操作

在`build_open_flags`函数完成后，我们建立了`flags`和`modes`。

### 3.1 获取`filename`

接下来调用`getname`函数获取`filename`结构体，得到系统调用所需的文件名：

```C
	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);
```

`getname`函数在[fs/namei.c](https://github.com/torvalds/linux/blob/v5.4/fs/namei.c#L207)文件中定义，如下：

```C
struct filename *
getname(const char __user * filename)
{
	return getname_flags(filename, 0, NULL);
}
```

`getname`函数仅仅调用`getname_flags`函数然后返回它的结果。`getname_flags`函数的主要目的是调用`strncpy_from_user`从用户空间复制文件路径到内核空间。

`filename`结构体在[include/linux/fs.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/fs.h#L2510)头文件中定义，如下：

```C
struct filename {
	const char		*name;	/* pointer to actual string */
	const __user char	*uptr;	/* original userland pointer */
	int			refcnt;
	struct audit_names	*aname;
	const char		iname[];
};
```

字段说明如下：

* `name` -- 指向内核空间的文件路径指针；
* `uptr` -- 用户空间的原始指针；
* `aname` -- 来自审计上下文的文件名；
* `refcnt` -- 引用计数；
* `iname` -- 文件名，长度小于`PATH_MAX`；

### 3.2 获取文件描述符

接下来就是获取新的空闲文件描述符，如下：

```C
	fd = get_unused_fd_flags(flags);
```

`get_unused_fd_flags`函数获取当前程序打开文件的文件描述符表，根据最小值(`0`)、最大值(`RLIMIT_NOFILE`)和`flags`标志计算分配的文件描述符，并根据`flags`参数设置或清除`O_CLOEXEC`标志。

### 3.3 获取`file`

`do_sys_open`最后主要的步骤就是获取`file`结构，如下：

```C
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fsnotify_open(f);
			fd_install(fd, f);
			trace_do_sys_open(tmp->name, flags, mode);
		}
	}
```

`do_filp_open()`函数主要功能是转换文件路径到`file`结构体，`file`结构体描述程序里已打开的文件。如果参数有误，则`do_filp_open`执行失败，使用`put_unused_fd`函数释放文件描述符；否则，返回`file`结构体，并在当前程序的文件描述符表中存储这个`file`结构体。

现在让我们来简短看下`do_filp_open()`函数的实现。这个函数在[fs/namei.c](https://github.com/torvalds/linux/blob/v5.4/fs/namei.c#L3547)中实现。如下：

```C
struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	set_nameidata(&nd, dfd, pathname);
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}
```

首先，调用`set_nameidata`函数初始化`nameidata`结构体，该结构体提供指向文件[inode](https://en.wikipedia.org/wiki/Inode)的链接。这是`do_filp_open()`函数的主要功能之一，这个函数通过传递到`open`系统调用的的文件名获取`inode`。在 `nameidata`结构体被初始化后，调用`path_openat`函数获取`file`结构，如下：

```C
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
```

注意`path_openat`会被调用了三次，通过不同的方式打开文件。首先，Linux内核以[RCU](https://github.com/torvalds/linux/blob/v5.4/Documentation/RCU/whatisRCU.txt)模式打开文件，这是打开文件有效的方式。如果打开失败，以正常模式打开文件。第三种方式相对较少，仅在[nfs](https://en.wikipedia.org/wiki/Network_File_System)文件系统中使用。`path_openat`函数查找路径，尝试寻找与路径相符合的`dentry`(目录数据结构，Linux内核用来追踪记录文件在目录里层次结构)。

`path_openat`函数在[fs/namei.c](https://github.com/torvalds/linux/blob/v5.4/fs/namei.c#L3508)中定义。如下：

```C
static struct file *path_openat(struct nameidata *nd,
			const struct open_flags *op, unsigned flags)
{
	struct file *file;
	int error;

	file = alloc_empty_file(op->open_flag, current_cred());
	if (IS_ERR(file))
		return file;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(nd, flags, op, file);
	} else if (unlikely(file->f_flags & O_PATH)) {
		error = do_o_path(nd, flags, file);
	} else {
		const char *s = path_init(nd, flags);
		while (!(error = link_path_walk(s, nd)) &&
			(error = do_last(nd, file, op)) > 0) {
			nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
			s = trailing_symlink(nd);
		}
		terminate_walk(nd);
	}
	...
	...
}
```

`path_openat`从调用`alloc_empty_file()`函数开始。`alloc_empty_file()`分配一个新`file`结构体并做一些额外的检查，例如：是否打开超出了系统中能打开的文件的数量等。在我们获得已分配的新`file`结构体后，根据`flags`标志进行不同的处理，如：`O_TMPFILE`标志调用`do_tmpfile`；`O_PATH`标志调用`do_o_path`；其他情况下调用`path_init`函数。

`path_init`函数在进行真正的路径寻找前执行一些预备工作，从路径中的开始位置遍历路径和元数据，如：路径中的`inode` ，`dentry inode`等。路径的开始位置可能是根目录（`/`）或者当前目录，因为我们使用`AT_CWD`作为起点。

`path_init`之后是个循环，循环执行 `link_path_walk` 和 `do_last` 。`link_path_walk`函数进行名称解析，沿着给定路径行走的过程，这个程序逐步理除了最后一个组件部分的文件路径。处理过程包括检查权限和获得文件组件，当获取到一个文件的组件后，传递给`walk_component`函数，这个函数从`dcache`更新当前的目录入口或询问底层文件系统。重复这个处理直到完成所有的路径。`link_path_walk`执行后，`do_last`函数会基于`link_path_walk` 返回的结果填充`file`结构体。当我们完成文件路径中的最后一个组成部分时，`do_last`中的`vfs_open` 函数将会被调用。

`vfs_open`函数在[fs/open.c](https://github.com/torvalds/linux/blob/v5.4/fs/open.c#L911)中实现，主要功能是调用底层文件系统的打开操作。

现在，我们已经实现了`open`的功能，剩余的工作出现错误时返回和释放分配的资源。现在，我们的讨论就结束了，我们没有分析`open`系统调用**全部**的实现。我们跳过了一些内容，例如：从不同挂载点的文件系统打开文件，解析软链接等，但去查阅这些处理特征应该不会很难。这些要素不包括在**通用的** `open` 系统调用实现中，具体特征取决于底层文件系统。如果你对此感兴趣，可查阅特定[filesystem](https://github.com/torvalds/linux/tree/v5.4/fs)的`file_operations.open`回调函数。

## 4 结束语

本文详细分析了`open`系统调用的实现过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
