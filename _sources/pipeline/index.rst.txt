Overview
========

To support the default simulation models SimEng supplies, as well as improve the ease with which new models may be created, the SimEng library maintains a set of simulation components which represent discrete parts of a processor core.

There are several additional components designed to act as common resources shared between units:

* ``RegisterFileSet``: A set of register files, each containing register values for their respective register type.
* ``RegisterAliasTable``: A set of mapping tables to translate between physical registers and the corresponding architectural register.
* ``ReorderBuffer``: Holds an ordered list of 'in-flight' instructions, with facilities for committing instructions and rewinding register allocations.
* ``LoadStoreQueue``: Holds ordered queues of load/store instructions, with facilities for servicing memory accesses and checking for address clashes.
