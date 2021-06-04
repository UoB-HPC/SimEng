Overview
========

SimEng provides a number of default processor core models, which simulate the structure and behaviour of common processor archetypes.

Emulation
---------

The emulation model is the simplest default model, simulating a simple atomic "emulation-style" approach to processing the instruction stream: each instruction is processed in its entirety before proceeding to the next instruction. This model is not particularly well suited for modelling all but the simplest processors, but due to its simplicity is extremely fast, and thus suitable for rapidly testing program correctness.

In future, this model may be suitable for rapidly progressing a program to a region of interest, before hot-swapping to a slower but more detailed model.


In-Order
--------

The in-order model simulates a simple in-order pipelined processor core, with discrete fetch, decode, execute, and writeback stages. This model is capable of speculatively fetching instructions via a supplied branch prediction model, with a flush mechanism for mispredictions.

**Note:** Due to a lack of dependency handling, this model only supports single-cycle instructions, which necessitates a zero-cycle memory model. Attempting to use this model with a multi-cycle memory model will result in incorrect execution and undefined behaviour.

Out-of-order
------------

The out-of-order model simulates a complex superscalar out-of-order core, similar to those found in modern high-performance processors. This core contains the following pipeline stages:

- Fetch
- Decode
- Rename
- Dispatch/Issue
- Execute
- Writeback
- Commit

To facilitate out-of-order execution, this model contains the following features:

- A reorder buffer for holding in-flight instructions
- A reservation station for dependency management and instruction scheduling
- A load/store queue to enable out-of-order memory access while ensuring memory order correctness
- A register alias table to allow register renaming and false dependency elimination

This model also supports speculative execution, using a supplied branch prediction model, and is capable of selectively flushing only mispredicted instructions from the pipeline while leaving correct instructions in-place.
