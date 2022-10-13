Simulation Concepts
===================

A SimEng simulation consists of two core components: a :doc:`model <../models/index>` and an :doc:`architecture <../arch/index>`. The model describes the type and structure of the processor being simulated, while the architecture describes the instruction set and related mechanisms and features. This separation allows for reusing the same basic instruction set across a wide range of simulated processors, such as modelling in-order and out-of-order processors which both support Armv9.2-a. Similarly, similar processor designs with different instruction sets may use the same model, such as a ThunderX2 versus an Ivy Bridge or similar Intel Core processor; while one is ARMv8 and the other x86, they are both out-of-order processors with a unified reservation station and a similar arrangement of execution units.

The following information is concerned with those concepts whose interactions flow beyond the scope of the processor core or don't fit the description of a :doc:`Simulation Component <../components/index>`.

.. toctree::
   :maxdepth: 2

   instructions
   registers
   memory
   syscalls
   kernel