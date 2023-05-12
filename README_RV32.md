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
