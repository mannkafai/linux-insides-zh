# Linux启动过程 （第五部分）

## 0 内核解压缩

上一篇文件分析了Linux从保护模式切换到长模式的过程。现在我们已经进入了长模式，接下来继续内核启动的最后处理过程。

## 1 内核解压缩前的准备

现在已经跳转到64位的入口点，即`startup_64`，在[arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/head_64.S#L251)中实现。其处理过程如下：

### 1.1 重置段寄存器

在进入长模式后，首先重置除`%cs`外的段寄存器，包括：`%ds`,`%es`,`%ss`,`%fs`，`%gs`。

### 1.2 计算重定位地址

同上一篇中在`startup_32`中计算重定位类似，这里重新计算重定位地址，`%rbp`为加载内核的地址，`%rbx`为内核解压缩的目标地址。最终的解压地址为：`%rbx = %ebx + init_size - _end + %rbp`，即将解压缩地址移动到解压区域的尾部。

### 1.3 设置函数栈

将`%rsp`设置为栈底，为后面的函数调用建立函数栈。

### 1.4 调整GOT

根据加载的地址，重新计算GOT([Global Offset Table](https://en.wikipedia.org/wiki/Global_Offset_Table))中PLT(procedure linkage table)的地址。

从`_got`到`_egot`的循环，`%rdi`为调整的位置，`%rax`为上一次调整的位置。

```C
.Ladjust_got:
	/* Walk through the GOT adding the address to the entries */
	leaq	_got(%rip), %rdx
	leaq	_egot(%rip), %rcx
1:
	cmpq	%rcx, %rdx
	jae	2f
	subq	%rax, (%rdx)	/* Undo previous adjustment */
	addq	%rdi, (%rdx)	/* Apply the new adjustment */
	addq	$8, %rdx
	jmp	1b
2:
	ret
```

### 1.5 更新GDT

将在`32位`模式下设置的`GDT`按照`64位`模式更新。

```C
	/* Make sure we have GDT with 32-bit code segment */
	leaq	gdt(%rip), %rax
	movq	%rax, gdt64+2(%rip)
	lgdt	gdt64(%rip)
```

### 1.6 按需开启5级页表

目前，我们已经在长模式下并且开启了`4级页表`，现在检查是否开启`5级页表`([5-level paging](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/x86_64/5level-paging.rst))。但是，在长模式下设置和清除`CR4.LA57`会触发错误。所以，我们不能直接修改。

首先，我们需要关闭长模式和分页；

同时，为了处理`bootloader`在没有开启5级页表的情况可能将内核加载在超出`4G`地址空间外，我们需要低端内存作为[trampoline](https://en.wikipedia.org/wiki/Trampoline_(computing))在`4级页表`、`5级页表`之间跳转。

#### 1.6.1 分页前准备（`paging_prepare`）

`paging_prepare`函数在[arch/x86/boot/compressed/pgtable_64.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/pgtable_64.c#L110)定义。

其功能是：

1. 检查是否开启`5级页表`；在编译选择开启`CONFIG_X86_5LEVEL`、命令行中没有`no5lvl`、CPU支持5级页表同时满足情况下，开启5级页表；
2. 确定`trampoline`地址；调用`find_trampoline_placement`确定`trampoline_start`位置;
3. 保存`trampoline`信息；其过程中会调用`trampoline_32bit_src`；
4. 根据`%cr4`，`%cr3`寄存器值，修改`trampoline`信息；

#### 1.6.2 `trampoline_32bit_src`

`trampoline_32bit_src`在[arch/x86/boot/compressed/head_64.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/head_64.S#L573)中定义。

这个函数进行`5级页表`的按需切换，即修改`cr3`的值。

```C
	/* Check what paging mode we want to be in after the trampoline */
	cmpl	$0, %edx
	jz	1f

	/* We want 5-level paging: don't touch CR3 if it already points to 5-level page tables */
	movl	%cr4, %eax
	testl	$X86_CR4_LA57, %eax
	jnz	3f
	jmp	2f
1:
	/* We want 4-level paging: don't touch CR3 if it already points to 4-level page tables */
	movl	%cr4, %eax
	testl	$X86_CR4_LA57, %eax
	jz	3f
2:
	/* Point CR3 to the trampoline's new top level page table */
	leal	TRAMPOLINE_32BIT_PGTABLE_OFFSET(%ecx), %eax
	movl	%eax, %cr3
```

#### 1.6.3 `trampoline_return`

`trampoline_return`也在`head_64.S`中定义。在恢复函数栈后，调用`cleanup_trampoline`恢复trampoline信息。

### 1.7 重置标志寄存器

```C
	/* Zero EFLAGS */
	pushq	$0
	popfq
```

### 1.8 再次调整GOT

这次调整GOT，需要清除之前GOT的偏移量。

### 1.9 复制压缩内核到压缩位置

在计算了内核的重定位地址后，需要复制压缩内存到改地址。代码如下：

```C
/*
 * Copy the compressed kernel to the end of our buffer
 * where decompression in place becomes safe.
 */
	pushq	%rsi
	leaq	(_bss-8)(%rip), %rsi
	leaq	(_bss-8)(%rbx), %rdi
	movq	$_bss /* - $startup_32 */, %rcx
	shrq	$3, %rcx
	std
	rep	movsq
	cld
	popq	%rsi
```

通过两个`leaq`指令用`_bss-8`偏移和`%rip`,`%rbx`计算有效地址。`movsq`每次从`%rsi`复制8个字节到`rdi`。

`std`指令设置`DF`标志，意味着`%rsi`和`%rdi`会递减，即：从后往前复制这些字节。最后，我们用`cld`指令清除`DF`标志.

### 1.10 内核地址重定位（`relocated`）

接下来，我们计算重定位标签地址，跳转到改地址执行。`relocated`进行解压前的最后准备。在清空`.bss`节后，准备`extract_kernel`函数的参数并调用这个函数。如下：

```C
/*
 * Jump to the relocated address.
 */
	leaq	.Lrelocated(%rbx), %rax
	jmp	*%rax
	...	

.Lrelocated:
	...
/*
 * Do the extraction, and jump to the new kernel..
 */
	pushq	%rsi			/* Save the real mode argument */
	movq	%rsi, %rdi		/* real mode address */
	leaq	boot_heap(%rip), %rsi	/* malloc area for uncompression */
	leaq	input_data(%rip), %rdx  /* input_data */
	movl	$z_input_len, %ecx	/* input_len */
	movq	%rbp, %r8		/* output target address */
	movq	$z_output_len, %r9	/* decompressed length, end of relocs */
	call	extract_kernel		/* returns kernel location in %rax */
	popq	%rsi
```

`extract_kernel`函数需要6个参数，这6个参数按照[x86调用约定(X86 calling conventions)](https://en.wikipedia.org/wiki/X86_calling_conventions)传递，即：按照`RDI, RSI, RDX, RCX, R8, R9`的顺序传递。

* `rmode` - 指向`boot_params`结构体的指针；
* `heap` - 指向早期启动堆的起始地址`boot_heap`的指针；
* `input_data` - 指向压缩的内核，即 `arch/x86/boot/compressed/vmlinux.bin.bz2`的指针；
* `input_len` - 压缩的内核的大小；
* `output` - 解压后内核的起始地址；
* `output_len` - 解压后内核的大小；

## 2 内核解压缩（`extract_kernel`）

`extract_kernel`函数在[arch/x86/boot/compressed/misc.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/misc.c#L340)中实现，主要过程如下：

### 2.1 控制台初始化（`console_init`）

在检查`boot_params`参数后，获取图形化参数后，调用`console_init`函数初始化控制台。这里再次初始化控制台，是因为我们不知道是否从实模式开始，还是BootLoader引导加载的。

### 2.2 计算所需的内存空间

在获取RSDP地址后，保存空闲内存的起始和结束地址，计算需要的解压缩大小。调用`debug_putaddr`输出解压缩调试信息。

```C
	free_mem_ptr     = heap;
	free_mem_end_ptr = heap + BOOT_HEAP_SIZE;

	needed_size = max(output_len, kernel_total_size);
#ifdef CONFIG_X86_64
	needed_size = ALIGN(needed_size, MIN_KERNEL_ALIGN);
#endif
```

### 2.3 选择随机地址（`choose_random_location`）

`choose_random_location`函数在[arch/x86/boot/compressed/kaslr.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/compressed/kaslr.c#L848)中实现。Linux内核支持[KASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)，出于系统安全的原因，允许Linux内核解压缩到随机地址。其实现过程在下一篇中进行描述。

### 2.4 验证加载的内存地址

得到内核映射镜像地址后，检查计算的随机地址是否正确，如：地址是否对齐，是否超出范围等。验证失败后调用`error`函数。`error`函数输出错误信息后，并使CPU进入空闲状态。所有的检查正确后，可以看到熟悉的信息：

```text
Decompressing Linux... 
```

### 2.5 调用解压缩函数（`__decompress`）

接下来，我们调用`__decompress`函数解压内核镜像，如下：

```C
__decompress(input_data, input_len, NULL, NULL, output, output_len, NULL, error);
```

`__decompress`函数的实现取决于在内核编译期间选择什么压缩算法，支持`GZIP`, `BZIP2`, ...等算法。如下：

```C
#ifdef CONFIG_KERNEL_GZIP
#include "../../../../lib/decompress_inflate.c"
#endif
#ifdef CONFIG_KERNEL_BZIP2
#include "../../../../lib/decompress_bunzip2.c"
#endif
#ifdef CONFIG_KERNEL_LZMA
#include "../../../../lib/decompress_unlzma.c"
#endif
#ifdef CONFIG_KERNEL_XZ
#include "../../../../lib/decompress_unxz.c"
#endif
#ifdef CONFIG_KERNEL_LZO
#include "../../../../lib/decompress_unlzo.c"
#endif
#ifdef CONFIG_KERNEL_LZ4
#include "../../../../lib/decompress_unlz4.c"
#endif
```

### 2.6 解析ELF文件（`parse_elf`）

在内核解压过程使用[原地](https://en.wikipedia.org/wiki/In-place_algorithm)解压，我们还是要把内核移动到正确的地址。内核镜像是个`ELF`([Executable and Linkable Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format))格式文件。可以通过`readelf`输出所有的可加载段。

```bash
x86_64-elf-readelf -l linux-source-5.4.0/arch/x86/boot/compressed/vmlinux

Elf file type is DYN (Position-Independent Executable file)
Entry point 0x200
There are 5 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  LOAD           0x0000000000001000 0x0000000000000000 0x0000000000000000
                 0x00000000008d4910 0x00000000008f41c0  RWE    0x1000
  LOAD           0x0000000000000000 0x00000000008f5000 0x00000000008f5000
                 0x0000000000000000 0x0000000000012000  R      0x1000
  LOAD           0x00000000008d6000 0x0000000000907000 0x0000000000907000
                 0x0000000000000360 0x0000000000000360  R      0x1000
  DYNAMIC        0x00000000008d57e0 0x00000000008d47e0 0x00000000008d47e0
                 0x0000000000000130 0x0000000000000130  RW     0x8
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RWE    0x10

 Section to Segment mapping:
  Segment Sections...
   00     .head.text .rodata..compressed .text .rodata .dynsym .dynstr .hash .gnu.hash .eh_frame .got .data .dynamic .bss 
   01     .pgtable 
   02     .rela.dyn 
   03     .dynamic 
   04   
```

`parse_elf`将这些段加载到`choose_random_location`函数得到的`output`地址。主要过程如下：

#### 2.6.1 检查ELF签名

ELF文件的签名为``0x7F 'E' 'L' 'F'``，如果是无效的ELF文件时，输出错误信息并使CPU进入空闲状态。如下：

```C
	memcpy(&ehdr, output, sizeof(ehdr));
	if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
	   ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	   ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
	   ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		error("Kernel is not a valid ELF file");
		return;
	}
```

#### 2.6.2 移动可加载段

解压缩后的镜像是正确的ELF文件后，我们遍历ELF文件的程序头，将可加载的段以2MB大小对齐到outpu缓冲区中。如下：

```C
	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr = &phdrs[i];

		switch (phdr->p_type) {
		case PT_LOAD:
#ifdef CONFIG_X86_64
			if ((phdr->p_align % 0x200000) != 0)
				error("Alignment of LOAD segment isn't multiple of 2MB");
#endif
#ifdef CONFIG_RELOCATABLE
			dest = output;
			dest += (phdr->p_paddr - LOAD_PHYSICAL_ADDR);
#else
			dest = (void *)(phdr->p_paddr);
#endif
			memmove(dest, output + phdr->p_offset, phdr->p_filesz);
			break;
		default: /* Ignore other PT_* */ break;
		}
	}
```

### 2.7 处理重定位（`handle_relocations`）

`handle_relocations`实现依赖于`CONFIG_X86_NEED_RELOCS`内核配置选项，在开启时调用。这个函数计算实际加载的地址(`output`)和`LOAD_PHYSICAL_ADDR`的差值，进行内核重定位。

## 3 跳转到实际内核地址

在内核重定位后，从`extract_kernel`返回到`head_64.S`。`extract_kernel`的返回值为实际内核地址，存放在`%rax`寄存器中。

```C
/*
 * Jump to the decompressed kernel.
 */
	jmp	*%rax
```

## 4 结束语

本文描述了Linux内核在长模式的引导过程，从保护模式切换到长模式，解压内核文件后跳转到内核入口点，此时，我们已经完成了Linux内核的引导过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
