# 内核系统调用 （第四部分）

## 0 介绍

在前面的三部分中，我们分析了Linux内核中[系统调用](https://en.wikipedia.org/wiki/System_call)，并且了解到两个新概念：`vsyscall`和`vDSO`。

本文将分析在Linux内核中执行程序时发生了什么。

## 1 Linux是如何启动程序的？

从用户的角度来看，有许多不同的方式来启动应用程序。例如，我们可以从[shell](https://en.wikipedia.org/wiki/Unix_shell)运行程序或双击应用程序图标。无论我们如何启动此应用程序，Linux内核都会处理应用程序启动。

在这一部分，我们将考虑从shell启动应用程序的方式。众所周知，从shell启动应用程序的标准方法如下：我们只需启动[终端](https://en.wikipedia.org/wiki/Terminal_emulator)应用程序，只需要写入程序的名称，并且传递或不传递参数给我们的程序，例如：

```bash
$ ls --version
ls (GNU coreutils) 8.30
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Richard M. Stallman and David MacKenzie.
```

让我们考虑一下当我们从shell启动应用程序时会发生什么，当我们输入程序名称时shell会做什么，Linux内核会做什么等。由于我们只关注Linux内核，因此，我们不会详细考虑shell做了什么，不会考虑复杂的情况，例如子shell等。

我的默认shell是[bash](https://en.wikipedia.org/wiki/Bash_(Unix_shell))，因此，我们只考虑bash shell如何启动程序。`bash`和其他使用C语言编程的程序一样都是从[main](https://en.wikipedia.org/wiki/Entry_point)函数开始的。如果你查看`bash`的源码，将会在[shell.c](https://github.com/bminor/bash/blob/bash-5.0/shell.c#L360)文件中找到`main`函数。这个函数在开始工作的主线程循环之前做了很多不同的事情。例如：

* 检查并尝试打开`/dev/tty`;
* 检查shell是否在调试模式下运行；
* 解析命令行参数；
* 读取shell环境变量；
* 加载`.bashrc`和`.profile`配置文件；
* 等等

在这次操作之后，我们可以看到`reader_loop`函数。该函数在[eval.c](https://github.com/bminor/bash/blob/bash-5.0/eval.c#L61)源文件中定义，循环读取指令并执行。`reader_loop`函数检查并读取指定的程序名称和参数时，调用[execute_cmd.c](https://github.com/bminor/bash/blob/bash-5.0/execute_cmd.c#L382)中的`execute_command`函数。`execute_command`通过下面的函数调用链来逐项检查：

```text
execute_command
--> execute_command_internal
----> execute_simple_command
------> execute_disk_command
--------> shell_execve
```

检查项包括：是否需要启动`subshell`、是否内置`bash`函数等。在整个过程的最后，`shell_execve`函数调用`execve`系统调用：

```C
  execve (command, args, env);
```

`execve`系统调用的定义如下：

```C
int execve(const char *filename, char *const argv [], char *const envp[]);
```

`execve`函数通过指定的文件名，参数和环境变量来执行程序。

在我们的例子中，`execve`系统调用是第一个，例如：

```bash
$ strace ls
execve("/bin/ls", ["ls"], [/* 62 vars */]) = 0

$ strace echo
execve("/bin/echo", ["echo"], [/* 62 vars */]) = 0

$ strace uname
execve("/bin/uname", ["uname"], [/* 62 vars */]) = 0
```

因此，用户应用程序（如：`bash`）调用系统调用，我们已经知道下一步是Linux内核。

## 2 `execve`系统调用

### 2.1 `execve`函数调用链

在系统调用的第二部分中，我们分析了Linux内核中系统调用的整个处理过程。`execve`系统调用在[fs/exec.c](https://github.com/torvalds/linux/blob/v5.4/fs/exec.c#L1956)文件中实现，如下：

```C
SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	return do_execve(getname(filename), argv, envp);
}
```

可以看到`execve`系统调用需要三个参数，实现也非常简单，仅仅返回`do_execve`函数的结果。`do_execve`函数在同一个文件中实现，使用给定的参数和环境变量初始化两个指针后，返回`do_execveat_common`的执行结果。如下：

```C
int do_execve(struct filename *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}

static int do_execveat_common(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags)
{
	return __do_execve_file(fd, filename, argv, envp, flags, NULL);
}
```

`do_execveat_common`函数使用类似的参数集，但是它使用5个参数。第一个参数代表应用程序目录的描述符，当前设置为`AT_FDCWD`，即：给定的路径名是相对于调用进程的当前工作目录；第五个参数是标志，我们设置为0，稍后我们会看到。`do_execveat_common`的实现也非常简单，返回`__do_execve_file`函数的执行结果。`__do_execve_file`函数实现主要的工作，执行一个新程序，该函数需要6个参数，在`do_execveat_common`函数的基础上增加了第6个参数，表示`file`结构。

### 2.2 执行新程序的过程

#### 2.2.1 执行前必要的检查

`__do_execve_file`函数进行必要的检查，包括：`filename`指针是否为NULL、运行的进程数量是否超过系统限制。在不满足条件时返回；在满足这两个检查条件时，我们清除`PF_NPROC_EXCEEDED`标记位，以防止`execve`执行失败。如下：

```C
	if (IS_ERR(filename))
		return PTR_ERR(filename);

	if ((current->flags & PF_NPROC_EXCEEDED) &&
	    atomic_read(&current_user()->processes) > rlimit(RLIMIT_NPROC)) {
		retval = -EAGAIN;
		goto out_ret;
	}

	current->flags &= ~PF_NPROC_EXCEEDED;
```

#### 2.2.2 清除共享文件

接下来，我们调用[kernel/fork.c](https://github.com/torvalds/linux/blob/v5.4/kernel/fork.c#L2935)文件中`unshare_files`函数来清除当前任务的共享文件，以消除潜在的文件描述符泄漏。如下：

```C
	retval = unshare_files(&displaced);
	if (retval)
		goto out_ret;
```

#### 2.2.3 分配`bprm`

接下来，我们准备`struct linux_binprm`类型的`bprm`变量，`linux_binprm`结构在[include/linux/binfmts.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/binfmts.h#L17)文件中定义，该结构用于保存加载二进制文件时使用的参数，如：`vm_area_struct`类型的`vma`字段，表示加载程序时给定地址空间中地址连续的单个内存区域；`mm`字段是二进制内存描述符，指向内存顶部的指针。

首先，我们调用`kzalloc`函数为这个结构分配内存，并检查分配结果。如下：

```C
	retval = -ENOMEM;
	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if (!bprm)
		goto out_files;
```

正确分配后，调用`prepare_bprm_creds`函数准备`bprm`凭证。初始化`bprm`凭证，即：初始化`linux_binprm`结构中的`cred`结构。`cred`结构包含任务的安全上下文，例如：任务的[real uid](https://en.wikipedia.org/wiki/User_identifier#Real_user_ID)；任务的[real guid](https://en.wikipedia.org/wiki/Globally_unique_identifier)；`uid`和`guid`的[VFS](https://en.wikipedia.org/wiki/Virtual_file_system)操作等。在准备`bprm`凭证之后，我们调用`check_unsafe_exec`函数检查后，设置当前的进程为`in_execve`状态。如下：

```C
	retval = prepare_bprm_creds(bprm);
	if (retval)
		goto out_free;

	check_unsafe_exec(bprm);
	current->in_execve = 1;
```

#### 2.2.4 打开执行文件

在这些操作之后，我们调用`do_open_execat`函数来打开执行的文件。`do_open_execat`函数检查执行标记（`flags`）；查找并打开磁盘上执行文件；检查是否从不可执行的挂载点上加载文件，我们需要避免从不可执行的文件系统（如：[proc](https://en.wikipedia.org/wiki/Procfs)和[sysfs](https://en.wikipedia.org/wiki/Sysfs)）上执行二进制文件；初始化`file`结构并返回。之后，调用`sched_exec`函数获取最小负载的处理器，并将当前程序迁移过去。如下：

```C
	if (!file)
		file = do_open_execat(fd, filename, flags);
	retval = PTR_ERR(file);
	if (IS_ERR(file))
		goto out_unmark;

	sched_exec();
```

#### 2.2.5 确定执行程序的文件名

在此之后，我们根据`filename`和`fd`确定执行程序的文件名。如果`filename`为空设置为`none`；如果在当前阅读上下文（`AT_FDCWD`）或绝对路径时，设置为参数的文件名；否则，设置为`/dev/fd/%d`或者`/dev/fd/%d/%s`。如下：

```C
	bprm->file = file;
	if (!filename) {
		bprm->filename = "none";
	} else if (fd == AT_FDCWD || filename->name[0] == '/') {
		bprm->filename = filename->name;
	} else {
		if (filename->name[0] == '\0')
			pathbuf = kasprintf(GFP_KERNEL, "/dev/fd/%d", fd);
		else
			pathbuf = kasprintf(GFP_KERNEL, "/dev/fd/%d/%s",
					    fd, filename->name);
		if (!pathbuf) {
			retval = -ENOMEM;
			goto out_unmark;
		}
		if (close_on_exec(fd, rcu_dereference_raw(current->files->fdt)))
			bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;
		bprm->filename = pathbuf;
	}
	bprm->interp = bprm->filename;
```

在设置文件名（`filename`）的同时，我们还设置了解释器（`interp`）的名称。现在我们只是设置为相同的名称，稍后根据执行程序的格式使用程序解释器的真实名称进行更新。

#### 2.2.6 初始化`bprm`

接下来，初始化`bprm`中的`mm`, `env`, `arg`, `buf`等信息。如下：

```C
	retval = bprm_mm_init(bprm);
	if (retval)
		goto out_unmark;

	retval = prepare_arg_pages(bprm, argv, envp);
	if (retval < 0)
		goto out;

	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;

	retval = copy_strings_kernel(1, &bprm->filename, bprm);
	if (retval < 0)
		goto out;

	bprm->exec = bprm->p;
	retval = copy_strings(bprm->envc, envp, bprm);
	if (retval < 0)
		goto out;

	retval = copy_strings(bprm->argc, argv, bprm);
	if (retval < 0)
		goto out;
```

首先，调用`bprm_mm_init`函数初始化内存描述符（`mm`）和堆栈限制（`rlim_stack`），`mm`是个`mm_struct`结构，在[include/linux/mm_types.h](https://github.com/torvalds/linux/blob/v5.4/include/linux/mm_types.h#L370)中定义，表示进程的地址空间，如下：

```C
static int bprm_mm_init(struct linux_binprm *bprm)
{
	...
	bprm->mm = mm = mm_alloc();
	err = -ENOMEM;
	if (!mm)
		goto err;

	task_lock(current->group_leader);
	bprm->rlim_stack = current->signal->rlim[RLIMIT_STACK];
	task_unlock(current->group_leader);
	...
}
```

接下来，调用`prepare_arg_pages`函数计算环境变量和命令行参数的计数，如下：

```C
static int prepare_arg_pages(struct linux_binprm *bprm,
			struct user_arg_ptr argv, struct user_arg_ptr envp)
{
	unsigned long limit, ptr_size;

	bprm->argc = count(argv, MAX_ARG_STRINGS);
	if (bprm->argc < 0)
		return bprm->argc;

	bprm->envc = count(envp, MAX_ARG_STRINGS);
	if (bprm->envc < 0)
		return bprm->envc;
	...
	...
}
```

`count`函数在同一个文件中定义，计算`argv`数组中字符串的计数。`MAX_ARG_STRINGS`在[include/uapi/linux/binfmts.h](https://github.com/torvalds/linux/blob/v5.4/include/uapi/linux/binfmts.h#L16)中定义，表示`execve`系统调用的最大字符串数量。如下：

```C
#define MAX_ARG_STRINGS 0x7FFFFFFF

#define BINPRM_BUF_SIZE 256
```

接下来，调用`prepare_binprm`函数填充`uid`，填充`cred`，并从打开的文件中读取前`256`字节。读取前`256`字节用于检查可执行文件的类型，后续读取文件的剩余部分。如下：

```C
int prepare_binprm(struct linux_binprm *bprm)
{
	int retval;
	loff_t pos = 0;

	bprm_fill_uid(bprm);

	retval = security_bprm_set_creds(bprm);
	if (retval)
		return retval;
	bprm->called_set_creds = 1;

	memset(bprm->buf, 0, BINPRM_BUF_SIZE);
	return kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
}
```

接下来，调用`copy_strings_kernel`和`copy_strings`函数将可执行二进制的文件名、命令行参数和环境变量复制到`bprm`中。

在`bprm_mm_init`中设置了新程序堆栈的顶部。在复制命令行参数和环境变量前，堆栈顶部包含程序的文件名，我们将文件名存储到`exec`字段中。如下：

```C
	bprm->exec = bprm->p;
```

#### 2.2.7 执行`bprm`

现在我们已经填充了`bprm`，现在调用`exec_binprm`执行二进制程序文件，`exec_binprm`函数在同一个文件中实现。如下：

```C
	retval = exec_binprm(bprm);
	if (retval < 0)
		goto out;
```

首先，我们存储[pid](https://en.wikipedia.org/wiki/Process_identifier)和[命名空间](https://en.wikipedia.org/wiki/Cgroups)中的`pid`。如下：

```C
	old_pid = current->pid;
	rcu_read_lock();
	old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
	rcu_read_unlock();
```

接下来调用`search_binary_handler`函数获取二进制文件的可执行文件格式。目前，Linux内核支持以下二进制格式：

* `binfmt_script` -- 支持从[#!](https://en.wikipedia.org/wiki/Shebang_(Unix))开始的解析脚本程序，在[fs/binfmt_script.c](https://github.com/torvalds/linux/blob/v5.4/fs/binfmt_script.c#L168)中实现；
* `binfmt_misc` -- 支持根据Linux内核运行配置生成的二进制格式，在[fs/binfmt_misc.c](https://github.com/torvalds/linux/blob/v5.4/fs/binfmt_misc.c#L882)中实现；
* `binfmt_elf` -- 支持[ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)格式，在[fs/binfmt_elf.c](https://github.com/torvalds/linux/blob/v5.4/fs/binfmt_elf.c#L2398)中实现；
* `binfmt_aout` -- 支持[a.out](https://en.wikipedia.org/wiki/A.out)格式，在[fs/binfmt_aout.c](https://github.com/torvalds/linux/blob/v5.4/fs/binfmt_aout.c#L342)中实现；
* `binfmt_flat` -- 支持[flat](https://en.wikipedia.org/wiki/Binary_file#Structure)格式，在[fs/binfmt_flat.c](https://github.com/torvalds/linux/blob/v5.4/fs/binfmt_flat.c#L1026)中实现；
* `binfmt_elf_fdpic` -- 支持[ELF-FDPIC](http://elinux.org/UClinux_Shared_Library#FDPIC_ELF)格式，在[fs/binfmt_elf_fdpic.c](https://github.com/torvalds/linux/blob/v5.4/fs/binfmt_elf_fdpic.c#L81)中实现；
* `binfmt_em86` -- 支持在[Alpha](https://en.wikipedia.org/wiki/DEC_Alpha)设备上运行的[ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)格式，在[fs/binfmt_em86.c](https://github.com/torvalds/linux/blob/v5.4/fs/binfmt_em86.c#L117)中实现。

`search_binary_handler`函数遍历所有支持的二进制格式，逐个调用`load_binary`函数。如果是支持的可执行文件格式，将二进制文件映射到内存中以执行。如下：

```C
int search_binary_handler(struct linux_binprm *bprm)
{
	...
	...
retry:
	read_lock(&binfmt_lock);
	list_for_each_entry(fmt, &formats, lh) {
		if (!try_module_get(fmt->module))
			continue;
		read_unlock(&binfmt_lock);

		bprm->recursion_depth++;
		retval = fmt->load_binary(bprm);
		bprm->recursion_depth--;

		read_lock(&binfmt_lock);
		...
		...
	}
	read_unlock(&binfmt_lock);
	...
	...
}
```

如果`search_binary_handler`正确加载二进制文件，追踪`exec`事件，如下：

```C
	if (ret >= 0) {
		audit_bprm(bprm);
		trace_sched_process_exec(current, old_pid, bprm);
		ptrace_event(PTRACE_EVENT_EXEC, old_vpid);
		proc_exec_connector(current);
	}
```

#### 2.2.8 释放资源

从`exec_binprm`函数返回后，接下来我们释放之前分配的内存并返回。如下：

```C
	current->fs->in_exec = 0;
	current->in_execve = 0;
	rseq_execve(current);
	acct_update_integrals(current);
	task_numa_free(current, false);
	free_bprm(bprm);
	kfree(pathbuf);
	if (filename)
		putname(filename);
	if (displaced)
		put_files_struct(displaced);
	return retval;
```

如果在开始新程序过程中出现错误，跳转到对应的标记释放资源后返回。如下：

```C
out:
	if (bprm->mm) {
		acct_arg_size(bprm, 0);
		mmput(bprm->mm);
	}

out_unmark:
	current->fs->in_exec = 0;
	current->in_execve = 0;

out_free:
	free_bprm(bprm);
	kfree(pathbuf);

out_files:
	if (displaced)
		reset_files_struct(displaced);
out_ret:
	if (filename)
		putname(filename);
	return retval;
```

### 2.3 返回到用户空间

从`execve`系统调用处理程序返回后，我们的程序在正确加载的情况下将开始执行。这是因为，上下文相关信息已经设置了正确的值。`execve`系统调用不会将控制权返回给创建的进程，但是调用者进程的代码段、数据段和其他段被新的程序段替换。我们的应用程序退出时通过`exit`系统调用来实现。

### 2.4 ELF文件的加载过程

在上面的`exec_binprm`函数过程中，我们通过`search_binary_handler`函数来获取二进制文件的可执行文件格式。以`ELF`格式为例，我们描述二进制文件的加载过程。

`load_elf_binary`函数在[fs/binfmt_elf.c](https://github.com/torvalds/linux/blob/v5.4/fs/binfmt_elf.c#L673)中实现。如下：

```C
static int load_elf_binary(struct linux_binprm *bprm)
{
	...
	...
}
```

#### 2.4.1 文件格式检查

首先，检查缓冲区中`ELF`标志幻数，如果不是`ELF`文件，则退出。如下：

```C
	loc->elf_ex = *((struct elfhdr *)bprm->buf);

	retval = -ENOEXEC;
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;
```

#### 2.4.2 ELF格式检查

接下来，检查`ELF`文件结构平台、文件类型。如果，ELF文件不可执行或不是动态库，或者架构平台错误，则返回。如下：

```C
	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(&loc->elf_ex))
		goto out;
	if (elf_check_fdpic(&loc->elf_ex))
		goto out;
	if (!bprm->file->f_op->mmap)
		goto out;
```

#### 2.4.3 加载程序文件

接下来，加载程序头（phdr, program header），程序头信息以段（Segment）的形式描述。从磁盘中加载解释器段（PT_INTERP）和加载段（PT_LOAD）。在可执行程序中解释器段指定为`.interp`节，在`x86_64`架构下为`/lib64/ld-linux-x86-64.so.2`，加载段包括程序依赖的动态库文件等。如下：

```C
	elf_phdata = load_elf_phdrs(&loc->elf_ex, bprm->file);
	if (!elf_phdata)
		goto out;

	elf_ppnt = elf_phdata;
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
        ...
        ...
        ...
```

设置堆栈并将`ELF`二进制文件映射到内存中的正确位置。映射[bss](https://en.wikipedia.org/wiki/.bss)和[brk](http://man7.org/linux/man-pages/man2/sbrk.2.html)段，获取程序入口地址、及其他许多其他不同的事情来执行程序文件。

#### 2.4.4 开启新线程

在一切设置完成后，调用`start_thread`函数开启新任务后返回，如下：

```C
	start_thread(regs, elf_entry, bprm->p);
	retval = 0;
out:
	kfree(loc);
out_ret:
	return retval;
```

`start_thread`函数在[arch/x86/kernel/process_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/kernel/process_64.c#L476)中定义，如下：

```C
void
start_thread(struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp)
{
	start_thread_common(regs, new_ip, new_sp,
			    __USER_CS, __USER_DS, 0);
}
```

`start_thread`函数需要三个参数，`regs`--新任务的寄存器组；`new_ip`--入口点地址；`new_sp`--栈顶地址。根据函数名称我们可以理解为开启了新线程，但实际上并非如此，只是准备新任务运行前的寄存器。只是调用`start_thread_common`函数来实现。

`start_thread_common`函数在同一个文件中实现，如下：

```C
static void
start_thread_common(struct pt_regs *regs, unsigned long new_ip,
		    unsigned long new_sp,
		    unsigned int _cs, unsigned int _ss, unsigned int _ds)
{
	...
	...
	loadsegment(fs, 0);
	loadsegment(es, _ds);
	loadsegment(ds, _ds);
	load_gs_index(0);

	regs->ip		= new_ip;
	regs->sp		= new_sp;
	regs->cs		= _cs;
	regs->ss		= _ss;
	regs->flags		= X86_EFLAGS_IF;
	force_iret();
}
```

`start_thread_common`函数用`0`填充`fs`寄存器，使用`_ds`填充`es`和`ds`寄存器值；接下来，设置`ip`, `sp`等寄存器值；最后，调用`force_iret`宏强制系统调用通过`iret`返回。

`ip`寄存器中保存的值即下次调度时运行的位置，即我们设置的入口点位置。

## 3 结束语

本文在系统调用的基础上详细分析了Linux下通过中断启动程序的整个过程。详细分析了`execve`系统调用的执行过程，并了解了`ELF`文件的加载过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
