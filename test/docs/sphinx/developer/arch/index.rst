Architectures
=============

SimEng architecture definitions are responsible for describing the features and behaviour of specific Instruction Set Architectures (ISAs) in a standardised way, allowing SimEng to model processors that use these ISAs while itself remaining ISA agnostic.

To achieve this, SimEng defines a set of abstract architecture-related classes. Discrete implementations of these classes are provided for each of the ISAs SimEng supports by default, and must also be implemented for adding support for new or custom ISAs.

ISA support is achieved through the use of the `Capstone <https://github.com/aquynh/capstone/>`_ disassembly framework, which disassembles a binary instruction into a C/C++ object that include operand registers, access types, and immediate values to name a few. In order to update SimEng's AArch64 support from Armv8.4-a to Armv9.2-a, we undertook a Capstone update to allow for disassembly of the Armv9.2-a ISA. The work done for this can be found `here <https://github.com/capstone-engine/capstone/pull/1907>`_, and other useful ISA updating tools present in Capstone can be found `here <https://github.com/capstone-engine/capstone/tree/next/suite/synctools>`_.

Below provides more information on the abstract structure of a SimEng architecture and currently supported ISAs. 

.. toctree::
   :maxdepth: 2

   abstract
   supported/aarch64
   supported/riscv