Pipeline Units
==============

SimEng supplies a set of standard self-contained "units", which represent the logic for the various stages of a processor pipeline. These units provide a ``tick`` method, which performs a single cycles's work when called. When ticked, each unit typically reads from the head of an input ``PipelineBuffer`` and writes to the tail of an output ``PipelineBuffer``. These buffers can be used to chain stages together---with the output from one unit acting as the input to another---to form a complete pipeline. Ticking the buffers at the end of each cycle will cause data to move from the tail to the head, ready to be processed by units in the next cycle.

The available units are:

* ``FetchUnit``: Reads instruction data from memory, to produce a stream of macro-ops.
* ``DecodeUnit``: Reads macro-ops from the input, breaks them into micro-ops, and writes them to the output.
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

Each cycle, it will process the most recently fetched memory block by passing it to the supplied ``Architecture`` instance for pre-decoding into macro-ops. The current program counter is passed to the supplied branch predictor: if the instruction is predicted to be a taken branch, then the PC will be updated to the predicted target address and the cycle will end, otherwise, the PC is incremented by the number of bytes consumed to produce the pre-decoded macro-op, and the remaining bytes in the block are once again passed to the architecture for pre-decoding.

This process of pre-decoding, predicting, and updating the PC continues until one of the following occurs:

.. glossary::

  The maximum number of fetched macro-ops is reached
    The current block is saved and processing resumes in the next cycle.
   
  A branch is predicted as taken
    A block of memory from the new address may be requested, and processing will resume once the data is available.

  The fetched memory block is exhausted
    The next block may be requested, and processing will resume once the data is available.

If at the beginning of the cycle the output buffer is stalled, the fetch unit will idle and perform no operation.

Fetching memory
***************

As the program counter may be updated by numerous external components thoughout the course of a single cycle, the fetch unit does not perform any memory requests automatically. **The next block must be requested manually**, by calling the ``requestFromPC`` function. It is advised to do this at the end of a cycle, once all possible sources of PC updates have been completed.


DecodeUnit
----------

TODO

RenameUnit
----------

TODO

DispatchIssueUnit
-----------------

TODO

ExecuteUnit
-----------

TODO

WritebackUnit
-------------

TODO
