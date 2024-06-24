---
name: SimEng Bug or Issue Report
about: Report a bug or un-expected SimEng behaviour
title: ''
labels: ''
assignees: ''

---

**Check List**
 [ ] The binary I am trying to run has been compiled statically for either RV64 or AArch64.
 [ ] The compiled binary is a Linux Elf file.
 [ ] I have provided both a config file and a binary to SimEng as runtime arguments.

**Binary File Information**
Please run `file` on the binary used and paste the output below (i.e. `file myBinary.elf`).
```bash
```

**System Description**
Please provide the following as a list:
 - The Operating System of the system you are running SimEng on
 - The compiler used to compile SimEng and its version
 - The compiler used to compile the static binary and its version
 - The ISA or specific processor that the binary was compiled for
   - For example, if `-march=armv8.4-a+sve` was used, then present `armv8.4-a+sve`
   - If `-mcpu=neoverse-v1` or similar was used, then present `neoverse-v1`
 - The processor of the system you are running SimEng on
 - The main memory capacity of the system you are running SimEng on

**SimEng Version**
Provide the SimEng repository branch, commit hash, and version tag (if relevant) that the issue is present on.

**SimEng CMAKE Options Used**
Provide a bullet list of all CMAKE options used. E.g. `-DCMAKE_BUILD_TYPE=Release`.

**Binary Compilation Instructions**
Provide a bullet list of how the binary in question was compiled, including all compiler flags used.

**SimEng Command Line Expression**
Provide the command line expression used to run SimEng e.g. `./simeng /path/to/configs/a64fx.yaml /path/to/myBinary.elf`

**SimEng Metadata Output**
If your simulation begins to execute the binary, please provide the metadata that SimEng prints at the start of execution.
E.g.
```bash
./simeng configs/a64fx.yaml myStaticBinary.elf 
[SimEng] Build metadata: 
[SimEng]        Version: 0.9.6 
[SimEng]        Compile Time - Date: 14:01:44 - Jun 19 2024 
[SimEng]        Build type: Debug 
[SimEng]        Compile options: $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>;-Wall;-pedantic;-Werror 
[SimEng]        Test suite: ON 

[SimEng] Running in Out-of-Order mode 
[SimEng] Workload: /home/SimEng/myStaticBinary.elf 
[SimEng] Config file: /home/SimEng/configs/a64fx.yaml 
[SimEng] ISA: AArch64
[SimEng] Auto-generated Special File directory: True 
[SimEng] Special File directory used: /home/SimEng/build/specialFiles/ 
[SimEng] Number of Cores: 1 
[SimEng] Starting...
```

**Problem Description**
Explain what you think should happen, and what actually happens.
