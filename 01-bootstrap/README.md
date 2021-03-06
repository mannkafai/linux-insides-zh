# 内核引导过程

本章介绍了Linux内核引导过程。

* [BIOS引导阶段](01-bootstrap-1.md) - 介绍了开机启动后BIOS和BootLoader的引导过程;
* [实模式的引导过程](01-bootstrap-2.md) - 介绍了在Linux内核在实模式下的引导过程。你会看到堆的初始化，查询不同的参数，如 EDD，IST 等...
* [从实模式切换到保护模式](01-bootstrap-3.md) - 介绍了内核从实模式切换到保护模式的过程。
* [从保护模式切换到长模式](01-bootstrap-4.md) - 介绍切换到长模式的准备工作以及切换的细节。
* [内核解压缩](01-bootstrap-5.md) - 介绍了内核解压缩之前的准备工作以及解压缩的细节。
* [内核地址随机化](01-bootstrap-6.md) - 介绍了Linux内核加载地址随机化的细节。
