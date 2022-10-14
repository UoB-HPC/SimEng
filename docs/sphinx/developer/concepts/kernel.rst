Kernel
======

The Kernel used in SimEng is an emulation of a Linux Kernel. The SimEng Kernel does not seek to provide the full functionality of a Linux Kernel. Instead, it provides the functionality for creating the program memory space and aid the emulation of system calls by maintaining a system and process state.

The SimEng Kernel is split into two classes, ``LinuxProcess`` and ``Linux``.

LinuxProcess
------------

The ``LinuxProcess`` class provides the functionality to process the supplied program. It creates the initial process memory space, including the Executable and Linkable Format (ELF) process image and the stack.
The process memory space created contains all date required by the program to run.

ELF Parsing
~~~~~~~~~~~~
The ELF binaries have a defined structure for 32-bit and 64-bit architectures, all information regarding parsing ELF binaries has been refereced from the `Linux manual page <https://man7.org/linux/man-pages/man5/elf.5.html>`_.
The ELF binary is divided into multiple parts. SimEng stores all relevant parts of the `ELF Binary` in a ``char[] processImage`` array, which is private member variable of the ``LinuxProcess`` class.

 **ELF Header**

 This is First part of ELF binary is the `ELF Header`, for 64-bit architecture the ``elf64_hdr`` struct in the Linux source tree defines the ELF Header. The first member of struct ``unsigned char e_indent`` holds information related to interpreting the ELF binary
 independant of the processor or the file's remaining contents. The first four bytes of ``e_indent`` holds the ELF magic number, which is used to identify the binary. The fifth byte of ``e_ident`` identifies the architecture of the binary.
 The ``e_entry`` member of the ELF header presents the entry point of the binary i.e. the virtual address to which the system first transfers control, thus starting execution.  The ``e_phoff`` member variables of the `ELF Header` stores the virtual address of `ELF Program Headers` whereas
 the size of each entry is stored by the ``e_phentsize`` member variable.

 **ELF Program Headers**
 
 Like the `ELF Header` the `ELF Program Header` is also defined by struct in the Linux source tree called ``Elf64_Phdr``.The ELF Program header table is an array of structures, each describing a segment or other information the system needs to prepare the program for
 execution. An object file segment contains one or more sections. `ELF Program Headers` are meaningful only for executable and shared object files.
 The ``p_vaddr`` member variable of the `ELF Program Header` holds the offset from the beginning of the file at which the first byte of the segment resides where as the ``p_memsz`` member holds the number of bytes in the memory image of the segment. SimEng uses these member variables to loop through all `ELF Program Headers` and looks for the `ELF Program Header` with largest value of ``p_vaddr``.
 SimEng uses the largest virtual address and size assosciated with that `ELF Prgram Header` to create a very large array called ``ElfProcessImage`` which can hold all `ELF Program Headers`. However, this way SimEng ends up creating a sparse array, in which most of the entries are unused. Also SimEng internally treats these virtual address as physical addresses to index into this large array.

 Each `ELF Program Header` also contains a member variable called ``p_type`` which describes the type of segment and how to interpret it. The value ``PT_LOAD=1`` represents a loadable segment i.e  the segment contains initialized data that contributes to the program's
 memory image. SimEng only stores the segments of `ELF Program Headers` with ``p_type == PTLOAD``. This completes the creation of the ``ElfProcessImage``.

After the ``ElfProcessImage`` has been created the ``LinuxProcess`` class creates an array ``char[] processImage``. The size of ``processImage`` is much larger than ``ElfProcessImage``, SimEng  adds the ``HEAP_SIZE`` and ``STACK_SIZE`` values specified the YAML configuration file to the 32-byte aligned value of ``ElfProcessImage`` size.
After this, SimEng proceeds to create a process stack around ``processImage``. The population of the initial stack state is based on the information `here <https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html>`_. 
 
 
To date, note that the only environment variable set is ``OMP_NUM_THREADS=1``, however, functionality to add more is available.

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
