# SimEng Updates to support 32-bit RISC-V ISA

- Added 32-bit RISC-V Architecture support
  - Sample implementation of how a 32 bit mode can be supported as a configuration. The necessary updates to Architecture, Instruction decode and Instruction execution is added.
  - Added a Demo yaml file DEMO_RISCV32.yaml that can be used as a reference for running using the emulation core.
  - The exception handler is updated to process a 32-bit register value for only 4 system calls that where used for internal benchmarks but will need wider adoption accross all other system calls.
- Added Compressed (16-bit) ISA support
- Added Instruction trace generation support that can be used to log commited instructions. 
- 32-bit CSR support
  - Added few CSRs that and sample implementation on how to use them.
- Added an alternative implementation of pipeline buffer with variable latency support. 
  - Supports 0 delay that is benefitial for merging pipeline stages if required.
  - Supports more than 1 cycle delay between pipeline stages.

# SimEng Update to share the sample implementation of the MicroController (MCU) class core model using 32-bit RISC-V ISA
- Small MCU like three stage pipeline core model
- Additonal fixed memory support for LSU in the mcu core
- Some update to ELF loader and SST image loading to SST memory
- Makefile to build and run
- Added support for memory mapped system registers,
- Used to add a HostTargetInterface for I/O and termination so that spike binaries can run on SimEng
- Added interrupt support;
- Fixed csrc handling;
- Fixed 32-bit sltiu instruction;
- Fixed 32-bit mulh, mulhu and mulhsu instructions
- Add support for interrupt by flushing the pipe at execution stage when an interrupt is visible, fix iteration count being int in main.cc
- Some bug fixes

# Capstone change required for RV32 compresses instruction usage in file include/capstone/capstone.h
CS_MODE_RISV32GC = CS_MODE_RISCV32 | CS_MODE_RISCVC, ///< RISCV RV32GC
- 
