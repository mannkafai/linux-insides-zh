# Linux启动过程 （第一部分）

## 0 从BIOS到引导程序

Linux的启动是一个非常复杂的过程。本文介绍从BIOS到引导程序(BootLoader)之间的执行过程。

## 1 BIOS引导阶段

在加电后，主板向[电源控制单元](https://en.wikipedia.org/wiki/Power_supply_unit_(computer))发送加电信号，在接收到加电正常的信号后，开始启动CPU。CPU开始启动时，重置(RESET)所有寄存器，将特定寄存器设置为固定的值。

以[80x86](https://en.wikipedia.org/wiki/X86)系列CPU为例，CPU在重置寄存器后，设置特定寄存器的值为：

```text
IP  0xfff0
CS  0xf000
```

这个阶段CPU工作在**实模式**([Real mode](https://en.wikipedia.org/wiki/Real_mode))。在实模式下，CPU只支持物理内存的访问，CPU提供`20-bit`地址总线，可以访问`1MB`的内存(`0x0 - 0xFFFFF`)；但寄存器是`16-bit`，最大支持访问`2^16 - 1`（`0xFFFF`，64K）的地址。

为了访问所有的地址空间，通过内存分段([Memory_segmentation](https://en.wikipedia.org/wiki/Memory_segmentation))将内存划分为多个固定大小的段，对内存位置的访问通过段(segment)和段内的偏移量(offset)组成。

在实模式下CPU使用`Code Segment (CS)`记录`segment`，`instruction pointer (IP)`记录`offset`，用`CS:IP`表示`segment:offset`。每个段的大小为64K，相应的地址的计算方式为：

```c
address = segment * 16 + offset
```

在segment和offset最大的情况下（`0xFFFF:0xFFFF`），地址为`0x10FFEF`(`0xFFFF * 16 + 0xFFFF`)，比实际能够访问的`1MB(0xFFFFF)`地址空间超出了`65520B`，在[A20 gate](https://en.wikipedia.org/wiki/A20_line)禁用的情况下变成了`0x0FFEF`。实模式下`CS`还有访问基址(base)，通过基址和`CS:IP`确定访问的地址。以`80286`为例，基址为`0xFF0000`，`CS:IP`为`0xF000:0xFFF0`，CPU访问的地址为`0xFFFFFFF0`。

CPU重置后寻找第一条指令的默认位置，叫做[重置向量（Reset vector）](https://en.wikipedia.org/wiki/Reset_vector)。硬件把这个地址(`0xFFFFFFF0`)映射到[ROM](https://en.wikipedia.org/wiki/Read-only_memory)芯片中，ROM中所存放的程序一般叫做[BIOS](https://en.wikipedia.org/wiki/BIOS)。

BIOS在启动过程中主要执行以下操作:

1. 对计算机硬件设备进行检测，检查计算机上安装的硬件设备及这些设备是否正常工作。这个过程叫做加电自检([POST, Power-on self-test](https://en.wikipedia.org/wiki/Power-on_self-test))，检测过程中错误信息通过显示器、指示灯及蜂鸣声提示。

   目前，80x86、AMD64等使用[ACPI](https://en.wikipedia.org/wiki/Advanced_Configuration_and_Power_Interface)标准。APCI建立许多表来描述当前系统中的硬件设备，这些表提供了操作系统和系统固件(BIOS或UEFI)之间的接口，可由操作系统读取后进行调用。

2. 始化系统设备，如鼠标、键盘、磁盘、光驱、硬盘、网卡、其他硬件、[集成外围设备](https://en.wikipedia.org/wiki/Motherboard#Integrated_peripherals)。确保不会引起IRQ线和I/O端口的冲突。

3. 加载引导程序。BIOS按照启动的优先级(用户可设置)，从引导设备(如：硬盘、软盘、CD/DVD，网络等)上定位[Bootloader](https://en.wikipedia.org/wiki/Bootloader)程序。这个过程中BIOS检查每个设备，尝试加载第一个扇区（引导扇区，[Boot_sector](https://en.wikipedia.org/wiki/Boot_sector)）检查是否可引导。有些BIOS会检查最后两个字节（扇区大小`512B`）是否为引导扇区签名(`0x55 0xAA`)来判断是否为引导设备。

4. 找到一个可引导设备后，将第一个扇区的内容拷贝到RAM中物理地址[`0x00007C00`](https://www.glamenv-septzen.net/en/view/6)开始的位置，然后跳转到这个地址，执行引导程序。

## 2 BootLoader

### 2.1 选择加载的操作系统

引导程序将操作系统的内核镜像加载到RAM中并移交执行，由操作系统进行自行初始化。目前常见的引导程序用[GRUB](https://www.gnu.org/software/grub/), [Syslinux](https://wiki.syslinux.org/wiki/index.php?title=The_Syslinux_Project), [bootmgr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bcdedit)等。大部分引导程序支持多个引导选择，支持从不同的分区进行多重引导。一些引导程序也可以加载其他引导程序，如：GRUB加载bootmgr。

以GRUB 2为例，在上个阶段，BIOS已经加载了引导扇区代码并跳转到`0x00007C00`的地址，从[boot](http://git.savannah.gnu.org/gitweb/?p=grub.git;a=blob;f=grub-core/boot/i386/pc/boot.S;hb=1998d63688080e59abda2092ff4b58a1eeb19b90#l119)开始执行，由于地址空间有限，在检查可引导的程序后，跳转到GRUB 2核心镜像的位置(即[diskboot](http://git.savannah.gnu.org/gitweb/?p=grub.git;a=blob;f=grub-core/boot/i386/pc/diskboot.S;hb=9dcac673ed08e874d883c6dc5af2017fb28eb3d5#l37))继续执行。GRUB 2加载完成核心镜像的其他部分后，执行[`grub_main`](http://git.savannah.gnu.org/gitweb/?p=grub.git;a=blob;f=grub-core/kern/main.c;hb=9e95f45ceeef36fcf93cbfffcf004276883dbc99#l266)函数。

`grub_main`函数进行控制台初始化、加载配置并解析grub配置文件、设置根设备、加载模块等，将grub转移到正常模式（[`grub_enter_normal_mode`](http://git.savannah.gnu.org/gitweb/?p=grub.git;a=blob;f=grub-core/normal/main.c;hb=cb2f15c544895e1f3d540dd39d36c4611bdf5b7b#l300)）。正常模式下，显示操作系统显示菜单，我们选择菜单后，执行`grub boot`命令并启动选择的系统。

### 2.2 系统镜像内存映射

Linux内核有一个引导协议（[Boot protocol](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/boot.rst)），详细描述了引导程序的加载linux内核的规范。GRUB 2在[`grub_cmd_linux`](http://git.savannah.gnu.org/gitweb/?p=grub.git;a=blob;f=grub-core/loader/i386/linux.c;hb=8fcfd1e0fc72d58766ce3dc09cf883c032f063f6#l647)函数实现linux内核的加载。

在QEMU中，我们通过指定内核的方式来启动Linux，qemu同样按照引导协议加载linux内核，在[x86_load_linux](https://github.com/qemu/qemu/blob/v6.1.0/hw/i386/x86.c#L761)函数中实现了内核的加载。

以`5.4.148`内核版本为例，Linux内核引导包括两个文件（`vmlinuz-5.4.148`和`initrd.img-5.4.148`），这两个文件包括三个部分的引导：

1. setup.bin：实模式下的系统引导程序；和vmlinux.bin共同组成[vmlinuz](https://en.wikipedia.org/wiki/Vmlinux)文件；
2. vmlinux.bin：保护模式下的系统引导程序；
3. initrd.img：[initial RAM disk](https://github.com/torvalds/linux/blob/v5.4/Documentation/admin-guide/initrd.rst);

引导设置文件（即`setup.bin`文件）的`0x01f1`偏移的位置开始为引导头，描述了引导细节([The Real-Mode Kernel Header](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/boot.rst#the-linuxx86-boot-protocol))。

内核引导设置头文件通过[arch/x86/boot/setup.ld](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/setup.ld#L6)和[arch/x86/boot/header.S](https://github.com/torvalds/linux/blob/v5.4/arch/x86/boot/header.S#L280)生成的。`header.S`对应的引导头代码如下：

```c
	.globl	hdr
hdr:
setup_sects:	.byte 0			/* Filled in by build.c */
root_flags:	.word ROOT_RDONLY
syssize:	.long 0			/* Filled in by build.c */
ram_size:	.word 0			/* Obsolete */
vid_mode:	.word SVGA_MODE
root_dev:	.word 0			/* Filled in by build.c */
boot_flag:	.word 0xAA55

	# offset 512, entry point

	.globl	_start
_start:
		# Explicitly enter this as bytes, or the assembler
		# tries to generate a 3-byte jump here, which causes
		# everything else to push off to the wrong offset.
		.byte	0xeb		# short (2-byte) jump
		.byte	start_of_setup-1f
```

根据引导协议规范，引导程序(BootLoader)根据读取的引导头内容，修改某些字段值，并将引导内容映射到内存中。不同版本的引导协议内存分布不同，调试过程中使用的linux内核版本为`5.4.148`，引导协议版本为`2.13`，内存映射分布如下：

```text
              ~                        ~
              |  Protected-mode kernel |
      100000  +------------------------+
              |  I/O memory hole       |
      0A0000  +------------------------+
              |  Reserved for BIOS     |      Leave as much as possible unused
              ~                        ~
              |  Command line          |      (Can also be below the X+10000 mark)
      X+10000 +------------------------+
              |  Stack/heap            |      For use by the kernel real-mode code.
      X+08000 +------------------------+
              |  Kernel setup          |      The kernel real-mode code.
              |  Kernel boot sector    |      The kernel legacy boot sector.
      X       +------------------------+
              |  Boot loader           |      <- Boot sector entry point 0000:7C00
      001000  +------------------------+
              |  Reserved for MBR/BIOS |
      000800  +------------------------+
              |  Typically used by MBR |
      000600  +------------------------+
              |  BIOS use only         |
      000000  +------------------------+

        where the address X is as low as the design of the boot loader permits.
```

`X`的值由引导程序决定的。QEMU设置的`X = 0x10000`，主要的内存映射过程如下：

```C
	//https://github.com/qemu/qemu/blob/v6.1.0/hw/i386/x86.c#L877
    if (protocol < 0x200 || !(header[0x211] & 0x01)) {
        /* Low kernel */
        real_addr    = 0x90000;
        cmdline_addr = 0x9a000 - cmdline_size;
        prot_addr    = 0x10000;
    } else if (protocol < 0x202) {
        /* High but ancient kernel */
        real_addr    = 0x90000;
        cmdline_addr = 0x9a000 - cmdline_size;
        prot_addr    = 0x100000;
    } else {
        /* High and recent kernel */
        real_addr    = 0x10000;
        cmdline_addr = 0x20000;
        prot_addr    = 0x100000;
    }

	//command line
	//https://github.com/qemu/qemu/blob/v6.1.0/hw/i386/x86.c#L924
    fw_cfg_add_i32(fw_cfg, FW_CFG_CMDLINE_ADDR, cmdline_addr);
    fw_cfg_add_i32(fw_cfg, FW_CFG_CMDLINE_SIZE, strlen(kernel_cmdline) + 1);
    fw_cfg_add_string(fw_cfg, FW_CFG_CMDLINE_DATA, kernel_cmdline);

	//initrd
	//https://github.com/qemu/qemu/blob/v6.1.0/hw/i386/x86.c#L1003
    initrd_addr = (initrd_max - initrd_size) & ~4095;

    fw_cfg_add_i32(fw_cfg, FW_CFG_INITRD_ADDR, initrd_addr);
    fw_cfg_add_i32(fw_cfg, FW_CFG_INITRD_SIZE, initrd_size);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_INITRD_DATA, initrd_data, initrd_size);

	//kernel and setup
	//https://github.com/qemu/qemu/blob/v6.1.0/hw/i386/x86.c#L1068
	fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_ADDR, prot_addr);
	fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_SIZE, kernel_size);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_KERNEL_DATA, kernel, kernel_size);

    fw_cfg_add_i32(fw_cfg, FW_CFG_SETUP_ADDR, real_addr);
    fw_cfg_add_i32(fw_cfg, FW_CFG_SETUP_SIZE, setup_size);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_SETUP_DATA, setup, setup_size);
```

### 2.3 执行控制移交

根据Linux引导协议中[Running the Kernel](https://github.com/torvalds/linux/blob/v5.4/Documentation/x86/boot.rst#running-the-kernel) 部分的描述。内核入口地址为实模式下内核基址后的第`0x20`段的偏移位置。代码如下：

```C
/* Note: in the case of the "old" kernel protocol, base_ptr must
   be == 0x90000 at this point; see the previous sample code */

seg = base_ptr >> 4;

cli();  /* Enter with interrupts disabled! */

/* Set up the real-mode kernel stack */
_SS = seg;
_SP = heap_end;

_DS = _ES = _FS = _GS = seg;
jmp_far(seg+0x20, 0);   /* Run the kernel */
```

QEMU设置的内核基址为`0x10000`，则内核入口地址为`0x1020:0x0000`，跳转后的寄存器的状态如下：

```c
// jmp_far(seg+0x20, 0); 
fs = gs = ds = es = ss = 0x1000
CS:IP = 0x1020:0x0000
```

### 2.4 映射内存转存分析

我们可以通过通过以下步骤转存内存信息：

```bash
(gdb) file vmlinux
(gdb) target remote :1234

#0x100000 is Protected-mode kernel base address
(gdb) b *0x100000
(gdb) c
(gdb) dump binary memory .dump_0x0_0x200000 0x0000 0x200000
```

对应的内存转存文件如下：

```text
...
0000ffd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0000ffe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
0000fff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
00010000: 4D 5A EA 07 00 C0 07 8C C8 8E D8 8E C0 8E D0 31    MZj..@..H.X.@.P1
00010010: E4 FB FC BE 40 00 AC 20 C0 74 09 B4 0E BB 07 00    d{|>@.,.@t.4.;..
00010020: CD 10 EB F2 31 C0 CD 16 CD 19 EA F0 FF 00 F0 00    M.kr1@M.M.jp..p.
00010030: 00 00 00 00 00 00 00 00 00 00 00 00 82 00 00 00    ................
00010040: 55 73 65 20 61 20 62 6F 6F 74 20 6C 6F 61 64 65    Use.a.boot.loade
00010050: 72 2E 0D 0A 0A 52 65 6D 6F 76 65 20 64 69 73 6B    r....Remove.disk
00010060: 20 61 6E 64 20 70 72 65 73 73 20 61 6E 79 20 6B    .and.press.any.k
00010070: 65 79 20 74 6F 20 72 65 62 6F 6F 74 2E 2E 2E 0D    ey.to.reboot....
00010080: 0A 00 50 45 00 00 64 86 04 00 00 00 00 00 00 00    ..PE..d.........
00010090: 00 00 01 00 00 00 A0 00 06 02 0B 02 02 14 80 B7    ...............7
000100a0: 90 00 00 00 00 00 80 56 26 02 F0 48 00 00 00 02    .......V&.pH....
000100b0: 00 00 00 00 00 00 00 00 00 00 20 00 00 00 20 00    ................
000100c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
000100d0: 00 00 00 10 B7 02 00 02 00 00 00 00 00 00 0A 00    ....7...........
000100e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
000100f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
00010100: 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00    ................
00010110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
00010120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
00010130: 00 00 00 00 00 00 00 00 00 00 2E 73 65 74 75 70    ...........setup
00010140: 00 00 E0 43 00 00 00 02 00 00 E0 43 00 00 00 02    ..`C......`C....
00010150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00    ................
00010160: 50 60 2E 72 65 6C 6F 63 00 00 20 00 00 00 E0 45    P`.reloc......`E
00010170: 00 00 20 00 00 00 E0 45 00 00 00 00 00 00 00 00    ......`E........
00010180: 00 00 00 00 00 00 40 00 10 42 2E 74 65 78 74 00    ......@..B.text.
00010190: 00 00 80 73 90 00 00 46 00 00 80 73 90 00 00 46    ...s...F...s...F
000101a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00    ................
000101b0: 50 60 2E 62 73 73 00 00 00 00 80 56 26 02 80 B9    P`.bss.....V&..9
000101c0: 90 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
000101d0: 00 00 00 00 00 00 80 00 00 C8 00 00 00 00 00 00    .........H......
000101e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF    ................
000101f0: FF 22 01 00 38 07 09 00 00 00 FF FF 00 00 55 AA    ."..8.........U*
00010200: EB 66 48 64 72 53 0D 02 00 00 00 00 00 10 40 38    kfHdrS........@8
00010210: B0 81 00 80 00 00 10 00 00 20 E0 B8 60 D3 1C 07    0.........`8`S..
00010220: 00 00 00 00 00 FE 00 00 00 00 02 00 FF FF FF 7F    .....~..........
00010230: 00 00 20 00 01 15 7F 00 FF 07 00 00 00 00 00 00    ................
00010240: 00 00 00 00 00 00 00 00 B1 03 00 00 A6 6D 8C 00    ........1...&m..
00010250: 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00    ................
00010260: 00 10 B7 02 90 01 00 00 8C D8 8E C0 FC 8C D2 39    ..7......X.@|.R9
...
```

## 3 结束语

本文描述了开机启动后BIOS和BootLoader的引导过程，目前BootLoader已经填充了Linux引导头设置文件，并跳转到对应的位置执行。

本系列文章翻译自[linux-insides](https://github.com/0xAX/linux-insides)，如果你有任何问题或者建议，请联系[0xAX](https://twitter.com/0xAX)或者创建 [issue](https://github.com/0xAX/linux-internals/issues/new)。

如果你发现中文翻译有任何问题，请提交[PR](https://github.com/mannkafai/linux-insides-zh)或者创建[issue](https://github.com/mannkafai/linux-insides-zh/issues/new)。
