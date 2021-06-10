Architectures
=============

SimEng architecture definitions are responsible for describing the features and behaviour of specific Instruction Set Architectures (ISAs) in a standardised way, allowing SimEng to model processors that use these ISAs while itself remaining ISA agnostic.

To achieve this, SimEng defines a set of abstract architecture-related classes. Discrete implementations of these classes are provided for each of the ISAs SimEng supports by default, and must also be implemented for adding support for new or custom ISAs.

Below provides more information on the abstract structure of a SimEng architecture and currently supported ISAs.

.. toctree::
   :maxdepth: 2

   abstract
   supported/aarch64