Pipeline Units
==============

The SimEng pipeline units provide a ``tick`` method, which performs a single cycles' work when called. When ticked, each unit typically reads from the head of an input ``PipelineBuffer`` and writes to the tail of an output ``PipelineBuffer``. These buffers can be used to chain stages together, with the output from one unit acting as the input to another, to form a complete pipeline. Ticking the buffers at the end of each cycle will cause data to move from the tail to the head, ready to be processed by units in the next cycle.

The available units are:

* ``FetchUnit``: Reads instruction data from memory, to produce a stream of macro-ops.
* ``DecodeUnit``: Reads macro-ops from the input, converts them into SimEng instruction objects as micro-ops, and writes them to the output.
* ``RenameUnit``: Reads micro-ops from the input, renames their operands, places an entry in a reorder buffer, and writes them to the output.
* ``DispatchIssueUnit``: Reads micro-ops from the input, reads operands from register files, and adds them to an internal queue until any missing operands have been broadcast. Writes execution-ready micro-ops to multiple outputs.
* ``ExecuteUnit``: Reads micro-ops from the input and holds them in an internal queue for a cycle-duration determined by their execution latency, after which they're written to the output.
* ``WritebackUnit``: Reads micro-ops from the input and writes results to register files.


FetchUnit
---------

The ``FetchUnit`` class models the fetch pipeline stage, and is responsible for reading instruction memory and generating a stream of macro-ops.

Behaviour
*********

The fetch unit fetches memory in discrete boundary-aligned blocks, according to the current program counter (PC); this is to prevent the fetched block overlapping an inaccessible or unmapped memory region that may result in the request incorrectly responding with a fault despite the validity of the initial region.

Each cycle, it will process the most recently fetched memory block by passing it to the supplied ``Architecture`` instance for pre-decoding into macro-ops. Once pre-decoded, the macro-op is passed to the supplied branch predictor: if the instruction is predicted to be a taken branch, then the PC will be updated to the predicted target address and the cycle will end, otherwise, the PC is incremented by the number of bytes consumed to produce the pre-decoded macro-op. The remaining bytes in the block are once again passed to the architecture for pre-decoding.

This process of pre-decoding, predicting, and updating the PC continues until one of the following occurs:

.. glossary::

  The maximum number of fetched macro-ops is reached
    The current block is saved and processing resumes in the next cycle.

  A branch is predicted as taken
    A block of memory from the new address may be requested, and processing will resume once the data is available.

  The fetched memory block is exhausted
    The next block may be requested, and processing will resume once the data is available.

If the output buffer is stalled when the cycle begins, the fetch unit will idle and perform no operation.

Fetching memory
***************

As the program counter may be updated by numerous external components throughout the course of a single cycle, the fetch unit does not perform any memory requests automatically. **The next block must be requested manually**, by calling the ``requestFromPC`` function. It is advised to do this at the end of a cycle from the core model, once all possible sources of PC updates have been completed.


DecodeUnit
----------

The ``DecodeUnit`` class models the decode stage of a processor pipeline, and is responsible for converting a stream of macro-ops into a stream of SimEng instructions.

Behaviour
*********

Each cycle, the decode unit will read macro-ops from the input buffer, and split them into a stream of ``Instruction`` objects.

.. Note:: The DecodeUnit is currently only capable of handling macro-ops that split into a single instruction: https://github.com/UoB-HPC/SimEng/issues/14

The now-decoded instructions are checked for any trivially identifiable branch mispredictions (i.e., a non-branch predicted as a taken branch), and if discovered, the branch predictor is informed and a pipeline flush requested.

The cycle ends when all macro-ops in the input buffer have been processed, or a misprediction is identified and all remaining macro-ops are flushed.

If the output buffer is stalled when the cycle begins, the decode unit will idle, perform no operation, and will flag its input buffer as having stalled, until the output is no longer stalled.


RenameUnit
----------

The ``RenameUnit`` class models the register renaming stage found in out-of-order processors, and is responsible for renaming the source and destination registers of an instruction to eliminate false dependencies.

Behaviour
*********

Each cycle, the rename unit will read instructions from the input stream, and perform the following operations:

1) Add the instruction to the supplied reorder buffer
2) Obtain up-to-date register mappings for each of the source operands from the supplied register alias table, and rename them in the instruction accordingly
3) Allocate new physical registers for each of the destination registers in the supplied register alias table, and rename them in the instruction accordingly
4) (Loads/stores only) Add the instruction to the supplied load/store queue

Before any of these steps occur, it is ensured that **all** of these steps are possible to carry out for the given instruction: if there is insufficient space in the reorder buffer, insufficient free registers to allocate for the destination registers, or insufficient load/store queue space (where applicable) then the unit will halt and stall the input buffer. If this occurs, processing will be re-attempted each subsequent cycle until successful, at which point the input will be unstalled and normal operation will resume.

Once an instruction is processed, it's written into the output buffer and the next instruction in the input buffer begins processing. This continues until the input buffer is empty.

If the output buffer is stalled when the cycle begins, the rename unit will idle, perform no operation, and will flag its input buffer as having stalled, until the output is no longer stalled.

Exceptions
**********

If an instruction has been flagged as having encountered an exception, then the rename stage will place it directly into the reorder buffer, skip renaming entirely, and **will not** write it to the output buffer.

.. todo::
  Verify that this doesn't cause issues with exception-generating load/store instructions, or problems with the register alias table caused by attempting to commit un-renamed registers.


DispatchIssueUnit
-----------------

The ``DispatchIssueUnit`` class models the dispatch/issue stages found in out-of-order processors, and is responsible for managing dependencies between instructions. This class contains a reservation station arrangement for holding instructions until their dependencies are met across one or more reservation stations, and uses a scoreboard and dependency matrix to track and handle dependencies.

While the ``DispatchIssueUnit`` has a single input buffer, it has multiple output buffers. Only a single instruction will ever be placed into any individual output buffer per cycle, even if they are wide enough to support multiple.

.. Note:: The terms "dispatch" and "issue" are often used inconsistently in computer architecture literature. In SimEng, dispatch refers to an instruction being placed into a reservation station, while issue refers to an instruction being removed from a reservation station and placed into an output port.

Behaviour
*********

Each cycle, the unit performs three discrete tasks: dispatch, operand forwarding, and issue. Dispatch occurs when the unit is ticked, while operand forwarding is expected to occur multiple times as other components in the pipeline generate results that must be delivered to pending instructions. Issue must be independently triggered later in the cycle, once all operand forwarding has concluded.

Dispatch
''''''''

During dispatch, the unit will read instructions from the input buffer, and check their required source operands against the internal scoreboard, the structure responsible for tracking operand availability. If an operand is available, it is supplied to the instruction; otherwise, an entry is inserted into the internal dependency matrix to track that the instruction depends on that missing operand.

Before operand checking, each instruction is allocated a destination port that corresponds to one of the output buffers. A supplied port allocator is used to determine the destination port of the supplied instruction. The logic of the port allocator can be model-independent but SimEng provides a basic ``BalancedPortAllocator`` class that attempts to balance port allocation amongst the available reservation stations for that instruction. A ``getRSSizes`` function is supplied to port allocator classes to support algorithms that rely on information relating to the occupancy of reservation stations. Within a port allocator, there also exists a ``tick`` function which, similarly to the pipeline units, allows for per-cycle logic to be triggered.

A reservation station can have many ports, with each port maintaining a ready queue containing instructions that are ready to execute. The port is also assigned an associated destination port number to map reservation station ports to output buffers. Note that there is no dedicated data structure for the instructions in the reservation stations; all instructions it contains are either in the dependency matrix or one of its associated port ready queues, so we simply keep track of the number of instructions instead.

The instruction is then assigned to a reservation station, where it will remain until issued. If at any point the reservation station becomes full while instructions remain in the input, the cycle stops and the input buffer becomes stalled. The remaining instructions will be processed during a future dispatch, once space is available, and the input buffer will be unstalled once emptied. 

Operand forwarding
''''''''''''''''''

When results are forwarded to the unit, the associated registers are looked up in the internal dependency matrix to find the instructions depending on them. The results are supplied to the dependent instructions, and the relevant dependency matrix entries cleared. Once an instruction has all of its dependencies met it is moved to the ready queue for its allocated port.

Issue
'''''

During issue, the ready queue for each port is checked for instructions that can be executed. If a ready instruction's allocated port is unstalled and has not yet been used this cycle, the instruction will be placed into it and removed from the queue; otherwise, it will be skipped and handled during a future issue stage.

ExecuteUnit
-----------

The ``ExecuteUnit`` class models the execute stage of a processor pipeline, and is responsible for handling the execution logic of instructions and broadcasting their results once completed. The unit maintains an internal pipeline, which queues instructions according to their execution latency before executing them.

.. Note:: ``ExecuteUnit`` represents a single functional/execution unit of a pipeline. As a result, only the first slot of the input/output buffers are used; models of superscalar processors with multiple execution units are expected to use multiple instances.

Behaviour
*********

Each cycle, a single instruction is read from the input buffer. The latency of the instruction is checked, and it is added to the internal pipeline queue, where it will remain for at least the duration of its instruction latency.

There exist two cases in which an execution unit may become stalled:

Pipeline blocking
  Some instructions require the use of an execution unit for many cycles to perform their operation. During this time, no other instruction may enter the internal execution pipeline and is deemed blocked.

.. _operation-blocking:  

Operation blocking
  An optional but similar method to pipeline blocking for a specific subset of instructions. The subset is denoted through the use of an instruction group value. If an instruction shares full or partial association with the chosen group, it is blocked from entering the internal pipeline. In the case of no shared association, an instruction may flow through the unit in a standard manner.

Once the input has been processed, the instruction at the head of the pipeline is checked to see if its latency has passed. If not, the cycle ends early, otherwise, the instruction proceeds to execution.

While normal data processing instructions are simply executed, some instruction types are treated slightly differently during execution:

.. glossary::
  Loads
    Address generation is performed, before passing the instruction to the unit's supplied load handling function. Unlike other instructions, load instructions **are not** written to the output buffer, as execution cannot occur until the memory read concludes. It is the responsibility of the load handling function to ensure that the instruction is executed and results broadcast once the loaded data is available.

  Stores
    Address generation is performed, and the instruction is executed to determine the memory data to be written. The instruction is passed to the unit's supplied store handler.

  Branches
    The instruction is executed, and queried to determine whether or not the results match the branch prediction originally associated with the instruction. If a misprediction is encountered, the branch predictor is informed, and a flush is raised to instruct the core to reset the program counter to the correct address and remove all incorrectly speculated instructions from the core.

For all instructions other than loads (as they are removed from the unit after address generation), once executed, the instruction is checked for any exceptions. If an exception was encountered, the instruction is passed to the unit's supplied exception handler. Otherwise, any register results are broadcast by calling the unit's supplied operand forwarding handler. In both cases, the instruction is then written to the unit's output buffer.


WritebackUnit
-------------

The ``WritebackUnit`` class models the writeback stage of a processor pipeline, responsible for writing the results from executed instructions to the register files, and marking them as ready to commit.

Behaviour
*********

Each cycle, the unit will read instructions from the input buffer, and retrieve any results generated during execution. All results are written to the supplied register file set, and the instructions are flagged as ready to commit. As the unit has no output buffer, instructions are discarded once writeback is complete.