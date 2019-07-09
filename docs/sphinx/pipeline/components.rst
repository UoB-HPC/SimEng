Common Components
=================

The SimEng library contains numerous components for use within the default models, as well as for facilitating the creation of custom models.

.. contents:: Contents

RegisterFileSet
---------------

The ``RegisterFileSet`` class models a set of register files, each containing any number of equally-sized registers. The default models each contain a single ``RegisterFileSet`` instance, with each register file within the set representing all registers of a discrete type (i.e., general purpose, floating point, etc.).

All data within the register files are stored as ``RegisterValue`` instances, and may be retrieved or modified using a ``Register`` identifier (see :ref:`registers` for more information).

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

