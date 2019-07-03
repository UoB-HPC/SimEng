Pipeline Components
===================

SimEng supplies a set of standard self-contained "units" are available, which represent the logic for the various stages of a processor pipeline. These units provide a ``tick`` method, which performs a single cycles's work when called. When ticked, each unit typically reads from the head of an input ``PipelineBuffer`` and writes to the tail of an output ``PipelineBuffer``. These buffers can be used to chain stages together---with the output from one unit acting as the input to another---to form a complete pipeline. Ticking the buffers at the end of each cycle will cause data to move from the tail to the head, ready to be processed by units in the next cycle.

The available units are:

* ``FetchUnit``: Reads instruction data from memory, to produce a stream of macro-ops.
* ``DecodeUnit``: Reads macro-ops from the input, breaks them into micro-ops, and writes them to the output.
* ``RenameUnit``: Reads micro-ops from the input, renames their operands, places an entry in a reorder buffer, and writes them to the output.
* ``DispatchIssueUnit``: Reads micro-ops from the input, reads operands from register files, and adds them to an internal queue until any missing operands have been broadcast. Writes execution-ready micro-ops to multiple outputs.
* ``ExecuteUnit``: Reads micro-ops from the input and holds them in an internal queue for a cycle-duration determined by their execution latency, after which they're written to the output.
* ``WritebackUnit``: Reads micro-ops from the input and writes results to register files.

There are several additional components designed to act as common resources shared between units:

* ``RegisterFileSet``: A set of register files, each containing register values for their respective register type.
* ``RegisterAliasTable``: A set of mapping tables to translate between physical registers and the corresponding architectural register.
* ``ReorderBuffer``: Holds an ordered list of 'in-flight' instructions, with facilities for committing instructions and rewinding register allocations.
* ``LoadStoreQueue``: Holds ordered queues of load/store instructions, with facilities for servicing memory accesses and checking for address clashes.
