Common Components
=================

The SimEng library contains numerous components for use within the default models, as well as for facilitating the creation of custom models.

.. contents:: Contents

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

At any point, a physical register may be "committed". This locks the physical register to the architectural register it represents, freeing the previously-allocated physical register. This increases the number of registers available to be allocated, at the cost of preventing safe rewind beyond this point. Register commitment is typically performed at instruction commitment/retirement, when the instruction's effects become irreversible and being able to rewind it is no longer necessary.

ArchitecturalRegisterFileSet
----------------------------

To handle the conceptual distinction between physical and architectural registers, some components use an ``ArchitecturalRegisterFileSet``, which guarantees that the registers accessed represent the architectural register identifier supplied. The base ``ArchitecturalRegisterFileSet`` class is a simple wrapper around a ``RegisterFileSet``, with accesses performed with a 1:1 mapping.

MappedRegisterFileSet
*********************

``MappedRegisterFileSet`` is an ``ArchitecturalRegisterFileSet`` implementation which uses a ``RegisterAliasTable`` to map between the supplied architectural register and a physical register in the underlying ``RegisterFileSet``.

.. Note:: For mappings to be valid, the ``RegisterAliasTable`` must be in a "synchronised" state, with no uncommitted mappings, otherwise mappings will point to registers expected to hold the specified value in future. To satisfy this, ``MappedRegisterFileSet`` instances should only be used during exception handling, after the simulation has terminated, or other similar situations where no in-flight instructions remain.

LoadStoreQueue
--------------

The ``LoadStoreQueue`` class models the load/store queue (LSQ) common to many out-of-order architectures. This structure contains in-order references to all in-flight load and store instructions, which it uses to ensure memory operations occur in program order.

To accommodate multiple varieties of LSQ, this model provides two modes: **split**, representing an LSQ with two discrete independently sized queues for holding loads and stores respectively, and **combined**, representing an LSQ with a single shared queue that holds both loads and stores.

All load and store instructions should be added to the LSQ in program order; this typically happens during the last in-order stage of an out-of-order model. In the default SimEng pipeline units, ``RenameUnit`` performs this task.

Loads
*****

When initially added to the LSQ, loads are considered pending: they exist primarily to hold their place in the queue, and aren't considered for memory order logic.

Once the addresses have been calculated for the load, the LSQ should be informed that the load operation can now be started. At this point, the LSQ will request the required data over the memory interface. Once these requests receive responses, during a later cycle, the data will be passed to the relevant load instructions and the load flagged as complete.

Once a completion slot is available, the load will be executed, the results broadcast to the supplied operand-forwarding handle, and the load instruction written into the completion slot. The load instruction will remain in the queue until it commits.

Stores
******

As with loads, stores are considered pending when initially added to the LSQ.

When the store instruction is committed, a memory-order violation check takes place: all loads in the LSQ are searched in ascending age order to see if their addresses overlap with the store. If any are discovered, a flush is triggered to re-execute the invalid load instruction and everything after it. The data from the store is then submitted to the memory interface as one or more write requests, and the store is removed from the queue.

Ticking
*******

The LSQ is expected to be ticked once per clock cycle. This tick is used to handle responses to memory read requests, and finish execution of completed load instructions.

Handling responses
    The memory interface is scanned for completed read requests. If any are present, the relevant load instruction is found and the data supplied, marking the load as complete.

Finishing execution
    Depending on the number of completion slots available, completed load instructions are identified and executed to arrange the loaded data into the output register format, before writing the instructions into the completion slots.

