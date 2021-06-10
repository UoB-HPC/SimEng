Kernel
======

The Kernel used in SimEng is an emulation of a Linux Kernel. The SimEng Kernel does not seek to provide the full functionality of a Linux Kernel. Instead, it provides the functionality for creating the program memory space and aid the emulation of system calls by maintaining a system and process state.

The SimEng Kernel is split into two classes, ``LinuxProcess`` and ``Linux``.

LinuxProcess
------------

The ``LinuxProcess`` class provides the functionality to process the supplied program. It creates the initial process memory space, including the Executable and Linkable Format (ELF) process image and the stack. The population of the initial stack state is based on the information `here <https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html>`_.

For the supplied program, the ``LinuxProcess`` class supports both statically compiled binaries and raw instructions in a hexadecimal format.

Linux
-----

The ``Linux`` class provides part of the functionality used to emulate system calls by maintaining a system and process state. These states contain information about the ``LinuxProcess`` class created from the supplied program. Such information includes:

- PID
- Program path
- Start location for brk system calls
- Current location of the most recent brk system call
- The initial stack pointer
- ``fileDescriptorTable`` that tracks the open file descriptors

All system call functionality is invoked within the ``Linux`` class, and any return value associated with the system call is generated here.
