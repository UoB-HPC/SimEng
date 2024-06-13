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

**System Description**
 - Operating System
 - Compiler used to compile SimEng and version
 - Compiler used to compile the static binary and version
 - ISA binary is targetting (i.e. armv8.4-a+sve)
 - Host Processor
 - Main Memory Capacity

**SimEng CMAKE Options Used**
Provide a bullet list of all CMAKE options used. E.g. `-DCMAKE_BUILD_TYPE=Release`.

**Binary Compilation Instructions**
Provide a bullet list of how the binary in question was compiled, including all compiler flags used.

**SimEng Command Line Expression**
e.g. `./simeng /path/to/configs/a64fx.yaml /path/to/myBinary.elf`

**Problem Description**
Explain what you think should happen, and what actually happens.
