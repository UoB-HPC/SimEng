Register Files
==============

SimEng provides a set of register related objects to aid and facilitate access to both physical and architectural registers.

RegisterFileSet
---------------

The ``RegisterFileSet`` class models a set of register files, each containing any number of equally-sized registers. The default models each contain a single ``RegisterFileSet`` instance, with each register file within the set representing all registers of a discrete type (i.e., general purpose, floating point, etc.).

All data within the register files are stored as ``RegisterValue`` instances, and may be retrieved or modified using a ``Register`` identifier (see :ref:`registers` for more information).

RegisterAliasTable
------------------

The ``RegisterAliasTable`` class models the register alias table (RAT) found in most out-of-order processors to facilitate register renaming as a method of false dependency elimination. This component is responsible for handling the mappings between the conceptual "architectural registers" that the architecture defines, and the raw "physical registers" that the core contains.

Each architectural register is assigned a corresponding physical register, and recorded in an internal mapping table. The RAT can translate an architectural register to its corresponding physical register when queried.

Allocation
**********

At any time, a new physical register may be allocated to an architectural register. The RAT keeps an internal list of unallocated ("free") physical registers, and will supply a new one and update its mapping table accordingly: future mapping queries on that architectural register will supply the newly allocated physical register instead.

The physical register previously allocated to the architectural register is internally recorded to facilitate rewinding (see below).

Rewinding
*********

It may sometimes be necessary to reverse the effects of an allocation - when an instruction is flushed, for example. The RAT provides a rewind system accordingly: the supplied physical register is freed, and the mapping table updated to reinstate the former physical register for the corresponding architectural register.

Committing
**********

At any point, a physical register may be "committed". This locks the physical register to the architectural register it represents, freeing the previously allocated physical register. This increases the number of registers available to be allocated, at the cost of preventing safe rewind beyond this point. Register commitment is typically performed at instruction commitment/retirement, when the instruction's effects become irreversible and being able to rewind it is no longer necessary.

ArchitecturalRegisterFileSet
----------------------------

To handle the conceptual distinction between physical and architectural registers, some components use an ``ArchitecturalRegisterFileSet``, which guarantees that the registers accessed represent the architectural register identifier supplied. The base ``ArchitecturalRegisterFileSet`` class is a simple wrapper around a ``RegisterFileSet``, with accesses performed with a 1:1 mapping.

MappedRegisterFileSet
*********************

``MappedRegisterFileSet`` is an ``ArchitecturalRegisterFileSet`` implementation which uses a ``RegisterAliasTable`` to map between the supplied architectural register and a physical register in the underlying ``RegisterFileSet``.

.. Note:: For mappings to be valid, the ``RegisterAliasTable`` must be in a "synchronised" state, with no uncommitted mappings, otherwise mappings will point to registers expected to hold the specified value in future. To satisfy this, ``MappedRegisterFileSet`` instances should only be used during exception handling, after the simulation has terminated, or other similar situations where no in-flight instructions remain.