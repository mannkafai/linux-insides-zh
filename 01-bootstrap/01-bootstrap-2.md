# Linux启动过程 （第二部分）

## 0 内核引导的过程

上一篇文件介绍了从BIOS到BootLoader之间的执行过程，现在已经进入Linux内核的引导过程。本文继续分析Linux在内核引导阶段的执行过程。目前CPU工作在实模式下，我们需要将其切换到保护模式下。

## 1 C函数调用前准备

引导程序加载内核镜像后，将控制权转交到内核引导程序，将地址跳转到`0x10200`(`0x1020:0x0000`)处，即：`arch/x86/boot/header.S`文件中[_start:](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/header.S#L291)位置。现在已经进行Linux内核的世界了。

```C
    #header.S#L291
	.globl	_start
_start:
		# Explicitly enter this as bytes, or the assembler
		# tries to generate a 3-byte jump here, which causes
		# everything else to push off to the wrong offset.
		.byte	0xeb		# short (2-byte) jump
		.byte	start_of_setup-1f
1:

```

`_start`的位置是跳转指令，跳转到`start_of_setup-1f`位置继续执行。`start_of_setup`位置的代码如下：

```C
    #header.S#L574
    .section ".entrytext", "ax"
start_of_setup:
# Force %es = %ds
	movw	%ds, %ax
	movw	%ax, %es
	cld
	...
	# Jump to C code (should not return)
	calll	main
```

`start_of_setup`的功能如下：

1. 设置寄存器的值`es = ds`;
2. 根据`ss`寄存器和`loadflags：CAN_USE_HEAP`的状态设置正确的`stack`;
3. 检查`setup_sig`是否为`0x5a5aaa55`；如果不正确提示错误；
4. 将`bss`段置零；
5. 调用`main`函数；

可用通过命令`objdump --disassemble-all arch/x86/boot/setup.elf >> arch/x86/boot/setup.elf.asm`查看对应的汇编代码。

`start_of_setup`对应的汇编代码如下：

```C
00000268 <start_of_setup>:
 268:	8c d8                	mov    %ds,%eax
 26a:	8e c0                	mov    %eax,%es
 26c:	fc                   	cld    
 26d:	8c d2                	mov    %ss,%edx
 26f:	39 c2                	cmp    %eax,%edx
 271:	89 e2                	mov    %esp,%edx
 273:	74 16                	je     28b <start_of_setup+0x23>
 275:	ba d0 58 f6 06       	mov    $0x6f658d0,%edx
 27a:	11 02                	adc    %eax,(%edx)
 27c:	80 74 04 8b 16       	xorb   $0x16,-0x75(%esp,%eax,1)
 281:	24 02                	and    $0x2,%al
 283:	81 c2 00 04 73 02    	add    $0x2730400,%edx
 289:	31 d2                	xor    %edx,%edx
 28b:	83 e2 fc             	and    $0xfffffffc,%edx
 28e:	75 03                	jne    293 <start_of_setup+0x2b>
 290:	ba fc ff 8e d0       	mov    $0xd08efffc,%edx
 295:	66 0f b7 e2          	movzww %dx,%sp
 299:	fb                   	sti    
 29a:	1e                   	push   %ds
 29b:	68 9f 02 cb 66       	push   $0x66cb029f
 2a0:	81 3e 98 45 55 aa    	cmpl   $0xaa554598,(%esi)
 2a6:	5a                   	pop    %edx
 2a7:	5a                   	pop    %edx
 2a8:	75 17                	jne    2c1 <setup_bad>
 2aa:	bf a0 45 b9 d3       	mov    $0xd3b945a0,%edi
 2af:	58                   	pop    %eax
 2b0:	66 31 c0             	xor    %ax,%ax
 2b3:	29 f9                	sub    %edi,%ecx
 2b5:	c1 e9 02             	shr    $0x2,%ecx
 2b8:	f3 66 ab             	rep stos %ax,%es:(%edi)
 2bb:	66 e8 90 10          	callw  134f <SYSSEG+0x34f>
	...
```

## 2 实模式下硬件初始化

经过上一步建立的栈，现在已经可用进行C函数调用。在`start_of_setup`的最后执行`calll	main`调用`main`函数，`main`函数在[arch/x86/boot/main.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/main.c#L134)中实现。`main`函数初始化计算机中的硬件设备，并为进入保护模式（Protect Mode)建立准备。

### 2.1 拷贝引导头信息到“零页”("zeropage")

`main`调用的第一个函数是`copy_boot_params`，改函数做了两件事：

1. 拷贝`header.S`中`hdr`信息到`boot_params`中的`struct setup_header hdr`;
2. 处理旧协议下`cmd_line_ptr`的地址；

`boot_params`的定义为`struct boot_params boot_params __attribute__((aligned(16)));`，可以看到`boot_params`以`16B`对齐。

`struct boot_params`在[arch/x86/include/uapi/asm/bootparam.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/uapi/asm/bootparam.h#L154)中定义，`struct setup_header hdr`对应的是[实模式引导头(the real mode kernel header)](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/boot.rst#the-real-mode-kernel-header)。

通过在[arch/x86/Makefile](https://github.com/torvalds/linux/blob/v5.4/arch/x86/Makefile#L34)中定义的`REALMODE_CFLAGS`，`REALMODE_CFLAGS`使用了GCC的`-mregparm=3`选项，使用`%ax`,`%dx`,`%cx`三个寄存器对应函数中的前三个输入参数。

`memcpy`在[arch/x86/boot/copy.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/copy.S#L18)中定义。调用方式如下：

```C
	//main.c#L39
	memcpy(&boot_params.hdr, &hdr, sizeof(hdr));
```

- `%ax`对应`boot_params.hdr`的地址；
- `%dx`对应`hdr`的地址；
- `%cx`对应`hdr`的大小；
  
### 2.2 控制台初始化

`console_init`在[arch/x86/boot/early_serial_console.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/early_serial_console.c#L148)定义，其功能为：

1. 在`command line`中找到`earlyprintk`参数后，初始化对应的控制台(串口的一种)的端口地址（port address）和波特率（baud rate）。`earlyprintk`支持`serial,0x3f8,115200`, `serial,ttyS0,115200`, `ttyS0,115200`三种选择。
2. 未找到`earlyprintk`的情况下，初始化`uart8250,io,0x3f8,115200n8`的控制台；

在控制台初始化、输入、输出等交互时，通过`inb/outb`进行数据或指令的交互。在控制台初始化完成后，可以看到第一条输出信息：

```C
	if (cmdline_find_option_bool("debug"))
		puts("early console in setup code\n");
```

`puts`在[arch/x86/boot/tty.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/tty.c#L61)中定义，通过`putchar`逐字节输出。

```C
void __attribute__((section(".inittext"))) putchar(int ch)
{
	if (ch == '\n')
		putchar('\r');	/* \n -> \r\n */

	bios_putchar(ch);

	if (early_serial_base != 0)
		serial_putchar(ch);
}
```

其中：

- `__attribute__((section(".inittext"))`指示该代码在`.inittext`段；
- `bios_putchar`通过`0x10`BIOS调用(`intcall(0x10, &ireg, NULL);`)将字符打印到屏幕上;
- `serial_putchar`通过`outb(ch, early_serial_base + TXR);`输出字符。

### 2.3 初始化堆（Heap）

`init_heap`检查`boot_params.hdr.loadflags`是否设置了`CAN_USE_HEAP`标记。

```C
	if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
		asm("leal %P1(%%esp),%0"
		    : "=r" (stack_end) : "i" (-STACK_SIZE));

		heap_end = (char *)
			((size_t)boot_params.hdr.heap_end_ptr + 0x200);
		if (heap_end > stack_end)
			heap_end = stack_end;
	} 
```

换而言之`stack_end = %esp - STACK_SIZE`，并确保`heap_end <= stack_end`。

### 2.4 验证CPU

`validate_cpu`在[rch/x86/boot/cpu.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/cpu.c#L73)定义，其功能为：

- 调用`check_cpu`([arch/x86/boot/cpucheck.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/cpucheck.c#L110))检查是否为所支持的CPU；如果是不支持的CPU进行提示；
- `check_cpu`检查CPU的标记，确保为支持长模式的64位CPU；`AMD`系列CPU开启`SSE+SSE2`；`Pentium M`系列CPU开启PAE等；

### 2.5 BIOS模式设置

`set_bios_mode`通过`0x15`BIOS调用告知CPU的模式。

### 2.6 检测内存分布

`detect_memory`在[arch/x86/boot/memory.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/memory.c#L116)定义，其功能为：逐步调用`detect_memory_e820();`,`detect_memory_e801();`,`detect_memory_88();`函数获取内存分布。

`detect_memory_e820`通过`0x15`BIOS调用获取内存分布情况。`struct boot_e820_entry`描述内存的分布情况，包括：起始地址（addr），大小（size），类型（type）。

### 2.7 初始化键盘

`keyboard_init`通过`0x16`BIOS调用获取键盘状态和设置键盘的响应速率（repeat rate）。

### 2.8 获取IST

`query_ist`通过`0x15`BIOS调用获取[Intel SpeedStep (IST)](https://en.wikipedia.org/wiki/SpeedStep)。

### 2.9 获取APM

`query_apm_bios`函数在`#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)`内核配置选项开启的情况下调用，在[arch/x86/boot/apm.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/apm.c#L19)中实现，通过`0x15`BIOS调用获取[Advanced Power Management](https://en.wikipedia.org/wiki/Advanced_Power_Management)。

### 2.10 获取EDD

`query_edd`在`#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)`内核配置选项开启的情况下调用，在[arch/x86/boot/edd.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/edd.c#L120)中实现。

`query_edd`从`0x80`开始获取BIOS支持的硬盘信息。`get_edd_info`通过`0x13`BIOS调用获取[EDD(Enhanced Disk Drive)](https://en.wikipedia.org/wiki/INT_13H#EDD)。在命令行参数中可以设置[EDD](https://github.com/torvalds/linux/blob/v5.4/Documentation/admin-guide/kernel-parameters.rst)的查询方式，包括：`skipmbr`, `skip`, `off`, `on`四种选项。其中`off`设置不获取EDD信息。

```C
	if (cmdline_find_option("edd", eddarg, sizeof(eddarg)) > 0) {
		if (!strcmp(eddarg, "skipmbr") || !strcmp(eddarg, "skip")) {
			do_edd = 1;
			do_mbr = 0;
		}
		else if (!strcmp(eddarg, "off"))
			do_edd = 0;
		else if (!strcmp(eddarg, "on"))
			do_edd = 1;
	}
	...
	for (devno = 0x80; devno < 0x80+EDD_MBR_SIG_MAX; devno++) {
		if (!get_edd_info(devno, &ei)
		    && boot_params.eddbuf_entries < EDDMAXNR) {
			memcpy(edp, &ei, sizeof(ei));
			edp++;
			boot_params.eddbuf_entries++;
		}

		if (do_mbr && !read_mbr_sig(devno, &ei, mbrptr++))
			boot_params.edd_mbr_sig_buf_entries = devno-0x80+1;
	}
```

### 2.11 设置视频模式

`set_video`在[arch/x86/boot/video.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/video.c#L317)中实现。

#### 1. vid_mode说明

`set_video`中首先从`boot_params.hdr.vid_mode`获取视频模式。BootLoader启动时必须填写`vid_mode`，从[Boot Protocol](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/boot.rst#details-of-harder-fileds)中可以读取改字段说明。

```text
Field name:	vid_mode
Type:	modify (obligatory)
Offset/size:	0x1fa/2
Please see the section on SPECIAL COMMAND LINE OPTIONS.
```

命令行参数说明：

```text
vga=<mode>
	<mode> here is either an integer (in C notation, either
	decimal, octal, or hexadecimal) or one of the strings
	"normal" (meaning 0xFFFF), "ext" (meaning 0xFFFE) or "ask"
	(meaning 0xFFFD).  This value should be entered into the
	vid_mode field, as it is used by the kernel before the command
	line is parsed.
```

QEMU处理命令行中`vga=`的代码如下，详细信息可参见：<https://github.com/qemu/qemu/blob/v6.1.0/hw/i386/x86.c#L936>

```C
    /* handle vga= parameter */
    vmode = strstr(kernel_cmdline, "vga=");
    if (vmode) {
        unsigned int video_mode;
        const char *end;
        int ret;
        /* skip "vga=" */
        vmode += 4;
        if (!strncmp(vmode, "normal", 6)) {
            video_mode = 0xffff;
        } else if (!strncmp(vmode, "ext", 3)) {
            video_mode = 0xfffe;
        } else if (!strncmp(vmode, "ask", 3)) {
            video_mode = 0xfffd;
        } else {
            ret = qemu_strtoui(vmode, &end, 0, &video_mode);
            if (ret != 0 || (*end && *end != ' ')) {
                fprintf(stderr, "qemu: invalid 'vga=' kernel parameter.\n");
                exit(1);
            }
        }
        stw_p(header + 0x1fa, video_mode);
    }
```

我们也可以在[arch/x86/include/uapi/asm/boot/h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/include/uapi/asm/boot.h#L6)看到相关定义：

```C
/* Internal svga startup constants */
#define NORMAL_VGA	0xffff		/* 80x25 mode */
#define EXTENDED_VGA	0xfffe		/* 80x50 mode */
#define ASK_VGA		0xfffd		/* ask for it at bootup */
```

#### 2. 重置堆（HEAP）

获取`vid_mode`后，调用`RESET_HEAP();`重置堆。其定义在[arch/x86/boot/boot.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/boot.h#L195)，代码如下：

```C
#define RESET_HEAP() ((void *)( HEAP = _end ))
```

与堆相关的函数还有如下：

- `GET_HEAP(type, n)`和`char *__get_heap(size_t s, size_t a, size_t n)`从堆中分配内存；
- `bool heap_free(size_t n)`判读堆是否可用；

#### 3. 存储模式参数

`store_mode_params`的功能如下：

1. 获取游标信息，`store_cursor_position`函数`0x10`BIOS调用;
2. 获取视频模式，`store_video_mode`函数`0x10`BIOS调用；
3. 设置`video_segment`。黑白模式(MDA, HGC, or VGA monochrome mode)为`0xb000`；彩色模式(CGA, EGA, VGA)为`0xb800`;
4. 获取字体信息，通过`fs`寄存器获取，如：`set_fs(0);`,`rdfs16(0x485);`；

#### 4. 存储屏幕信息

`save_screen`将屏幕信息存储到堆上。调用堆的代码如下：

```C
	if (!heap_free(saved.x*saved.y*sizeof(u16)+512))
		return;		/* Not enough heap to save the screen */

	saved.data = GET_HEAP(u16, saved.x*saved.y);
```

#### 5. 探测显卡

`probe_cards`在[arch/x86/boot/video-mode.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/video-mode.c#L31)中实现。遍历所有的显卡，获取显卡所支持的显示模式：

```C
	for (card = video_cards; card < video_cards_end; card++) {
		if (card->unsafe == unsafe) {
			if (card->probe)
				card->nmodes = card->probe();
			else
				card->nmodes = 0;
		}
	}
```

`video_cards`,`video_cards_end`在[arch/x86/boot/video.h](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/video.h#L82)声明：

```C
#define __videocard struct card_info __attribute__((used,section(".videocards")))
extern struct card_info video_cards[], video_cards_end[];
```

在[arch/x86/boot/setup.ld](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/setup.ld#L29)中`.videocards`内存段定义：

```C
	.videocards	: {
		video_cards = .;
		*(.videocards)
		video_cards_end = .;
	}
```

每个支持的显示模式（如：vga）定义如下：

```C
static __videocard video_vga = {
	.card_name	= "VGA",
	.probe		= vga_probe,
	.set_mode	= vga_set_mode,
};
```

`__videocard`是一个`card_info`结构体，定义如下：

```C
struct card_info {
	const char *card_name;
	int (*set_mode)(struct mode_info *mode);
	int (*probe)(void);
	struct mode_info *modes;
	int nmodes;		/* Number of probed modes so far */
	int unsafe;		/* Probing is unsafe, only do after "scan" */
	u16 xmode_first;	/* Unprobed modes to try to call anyway */
	u16 xmode_n;		/* Size of unprobed mode range */
};
```

`videocards`只是一个内存地址，所有的`card_info`结构都存放在这个段中，且存放在`video_cards`和`video_cards_end`之间，因此可以使用循环来遍历。

`card->probe`是一个函数地址，可以像正常函数一样调用，如：`video_vga.probe`指向`int vga_probe()`，通过`0x10`BIOS调用检查显卡的显示模式。

#### 6. 模式设置

在`probe_cards`执行完成后，进入模式设置。

模式设置是一个循环，如果是用户选择显示模式（`mode == ask`），显现一个菜单供用户选择。根据选择的模式或现有的`mode`值，调用`set_mode`来设置模式。成功设置后退出循环，否则设置模式为用户选择模式（`ask`）,继续选择模式后进行设置。

`set_mode`在[arch/x86/boot/video-mode.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/video-mode.c#L145)定义。检查`mode`值并进行转换后，调用`raw_set_mode`。`raw_set_mode`循环遍历所有的`card_info`，并调用`card->set_mode(mi)`功能。

`card->set_mode`同样是个函数地址，如：`video_vga.probe`指向`vga_set_mode(struct mode_info *mode)`，通过`0x10`BIOS调用设置不同的显示。

在显示模式正确设置后，将最终的显示模式设置到`boot_params.hdr.vid_mode`。

#### 7. 存储EDID信息

`vesa_store_edid`在[arch/x86/boot/video-vesa.c](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/video-vesa.c#L236)中定义。通过`0x10`BIOS调用，获取并设置[EDID](https://en.wikipedia.org/wiki/Extended_Display_Identification_Data)。

#### 8. 再次存储模式参数和恢复屏幕信息

新显示模式设置后，再次调用`store_mode_params`存储模式信息；设置了恢复标记后，调用`restore_screen`恢复之前记录的屏幕信息。

## 3 进入保护模式

在`main`函数的最后，调用`go_to_protected_mode`函数，做最后的准备并切换到保护模式。将在下篇继续分析。

## 4 结束语

本文描述了BootLoader引导后，Linux内核在实模式下的引导过程，包括：建立C函数调用环境、在实模式下硬件初始化等切换到保护模式前的准备工作。我们将在下一篇中继续分析切换保护模式的过程。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
