.. _registers:

Registers
=========

Instructions in SimEng primarily operate upon registers. Each instruction may request data from any number of registers, and may update any number of registers upon completion.

Registers are uniquely identified within SimEng using a ``Register`` object, consisting of a "type"---corresponding to a specific set of registers (i.e., general purpose, floating point, etc.)---and a "tag", which identifies an individual register within that set. The number of different types of registers, as well as the number and size of registers of each type, is defined by the architecture used.


RegisterValue
-------------

As the type of data stored in registers and passed between instructions is architecture-dependent, all data is represented using the ``RegisterValue`` class. This is essentially a thin wrapper around a byte array, and provides templated helper functions to read the data as the desired datatype.

A default-initialised ``RegisterValue`` has size 0, and will return ``false`` if evaluated as a bool.
