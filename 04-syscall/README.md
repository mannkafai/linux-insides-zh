# 系统调用

本章描述 Linux 内核中的系统调用概念。

* [系统调用概念简介](04-syscall-01.md) - 以`write`为例，介绍了系统调用的理论
* [系统调用的处理过程](04-syscall-02.md) - 介绍了系统调用发生时 Linux 内核执行的过程。
* [vsyscall和vDSO](04-syscall-03.md) - 介绍了 `vsyscall` 和 `vDSO` 概念。
* [Linux 内核如何启动程序](04-syscall-04.md) - 介绍了`execve`系统调用的执行过程，通过`execve`系统调用，Linux内核启动了一个新程序。
* [`open`系统调用的实现过程](04-syscall-05.md) - 介绍了`open`系统调用的实现过程。
* [Linux 资源限制](04-syscall-06.md) - 介绍了资源限制相关的系统调用的实现过程。
