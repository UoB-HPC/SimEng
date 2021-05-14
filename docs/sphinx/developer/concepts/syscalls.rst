System Calls
============

To support the simulation of programs that perform system calls, SimEng implements system call emulation. When a supervisor call exception is raised by the program, the :doc:`exception handler <../arch/abstract>` invokes the emulated operating system :doc:`kernel <kernel>` instance to perform the syscall.

Many syscalls are emulated entirely inside SimEng, with some exceptions detailed below.

File input/output
-----------------

Syscalls that interact with files are passed through to the host, in order to allow the simulated program to read and write data files on the host filesystem and interact with ``stdin``, ``stdout`` and ``stderr``. When a file is opened (e.g. with ``open`` or ``openat``), the emulated kernel maps the host file descriptor to a virtual file descriptor (``fileDescriptorTable``) which is returned to the simulated program. When handling syscalls that operate on file descriptors (e.g. ``lseek`` or ``writev``), the kernel looks up the corresponding host file descriptor in the map before passing the call onwards to the host.

The kernel detects attempts to open special files (such as those in ``/dev/`` or ``/proc``) and emulates their access inside SimEng rather than passing the call through to the host.
