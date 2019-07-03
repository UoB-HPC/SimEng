Overview
==========

A SimEng simulation consists of two core components: a *model* and an *architecture*. The model describes the type and structure of processor being simulated, while the architecture describes the instruction set and related mechanisms and features. This seperation allows for reusing the same basic instruction set across a wide range of simulated processors, such as modelling in-order and out-of-order processors which both support ARMv8. Similarly, similar processor designs with different instruction sets may use the same model, such as a ThunderX2 versus an Ivy Bridge or similar Intel Core processor; while one is ARMv8 and the other x86, they are both out-of-order processors with a unified reservation station and a similar arrangement of execution units.
