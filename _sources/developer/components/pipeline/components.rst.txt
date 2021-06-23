Common Components
=================

The SimEng library contains numerous components for use within the default models, as well as for facilitating the creation of custom models.

Reorder Buffer
--------------

The ``ReorderBuffer`` class models the in-order retirement/commitment buffer (Re-order buffer or ROB) common to many out-of-order architectures. A queue is maintained to store instructions and facilitate their in-order commitment from the simulated processor pipeline.

Reserve
*******

When the ``reserve`` function is called, the passed instruction is appended to the queue and assigned a sequence id. This sequence id is used throughout the remainder of the pipeline to distinguish the in-order position of the instruction, in relation to other instructions, when flowing out-of-order.

The instructions should be appended to the queue in program order; this typically happens during the last in-order stage of an out-of-order model. In the default SimEng pipeline units, ``RenameUnit`` performs this task.

Commit
******

The ``commit`` function is called in a similar fashion to other pipeline units' ``tick`` function. Each cycle, a set of instructions at the front of the queue have their state analysed. If the instruction has completed its flow through the processor pipeline, it is deemed ready to be committed. As to enforce the in-order commitment of instructions imposed by the ROB, any instruction at the head of the buffer that is not ready to be committed halts all instructions behind it from committing until it is ready. 

When an instruction is committed, any destination operands are committed to the architectural state and the processing of exceptions such as supervisor or system calls begin. Additionally, if the committed instruction is a store operation, all associated requests to memory are generated and possible memory order violations performed by out-of-order loads are checked for (described :ref:`here <store-retire>`).

Only a specific number of instructions can be committed per cycle as defined by the model.

LoadStoreQueue
--------------

The ``LoadStoreQueue`` class models the load/store queue (LSQ) common to many out-of-order architectures. This structure contains in-order references to all in-flight load and store instructions, which it uses to ensure memory operations occur in program order.

To accommodate multiple varieties of LSQ, this model provides two modes: **split**, representing an LSQ with two discrete independently sized queues for holding loads and stores respectively, and **combined**, representing an LSQ with a single shared queue that holds both loads and stores.

.. Todo::
    Allow for combined option to be defined via configuration files.

.. _lsq-restrict:

To enforce restrictions such as the number of loads/stores requests permitted per cycle, a secondary request queue, ``requestQueue_``, is utilised. This queue holds all distinct requests made by in-flight loads and stores, with some instructions having multiple entries due to multiple addresses requiring access. Additionally, the entries in this queue can only be processed after a defined number of cycles. This value is the pre-defined latency for a memory operation beyond that of the fixed L1 cache access latency. An internal clock is used to facilitate this delayed removal from the ``requestQueue_``.

All load and store instructions should be added to the LSQ in program order; this typically happens during the last in-order stage of an out-of-order model. In the default SimEng pipeline units, ``RenameUnit`` performs this task.

Loads
*****

When initially added to the LSQ, loads are considered pending: they exist primarily to hold their place in the load queue, and aren't considered for memory order logic.

Once the addresses have been calculated for the load, the LSQ should be informed that the load operation can now be started. At this point, all the addresses the load instruction has generated are placed into the ``requestQueue_``. Once an entry is selected in the ``requestQueue_``, the LSQ will send the required data over the memory interface as a read request. When these requests receive responses, during a later cycle, the data will be passed to the relevant load instructions and the load flagged as complete.

Once a completion slot is available, the load will be executed, the results broadcast to the supplied operand-forwarding handle, and the load instruction written into the completion slot. The load instruction will remain in the load queue until it commits.


.. _store-retire:

Stores
******

As with loads, stores are considered pending when initially added to the LSQ.

The generation of store instruction write requests are carried out after its commitment. The reasoning for this design decision is as followed. With SimEng supporting speculative execution, processed store instruction may come from an incorrectly speculated branch direction and will inevitably be removed from the pipeline. Therefore, it is important to ensure any write requests are valid, with respect to speculative execution, as the performance cost of reversing a completed write request is high.

Store write requests are placed into the ``requestQueue_`` similar to load read requests. Unlike load instructions read requests, the write requests are submitted to the memory interface prior to being selected from the ``requestQueue_``. Since store instruction write requests are appended to the ``requestQueue_`` after their commitment, we can be confident that the data to be stored and the order in which it is occurring is correct.

To minimise simulation errors, write requests are sent to the memory interface early. These errors derived from write requests occurring too late after a store instruction's commitment. Rarely, such latencies caused following load instructions to read incorrect data.

Although the write request has been submitted, it continues to occupy an entry in the ``requestQueue_`` to simulate the contention of LSQ resources between load and store operations (e.g. the number of permitted requests per cycle). Once selected from the ``requestQueue_``, the write request is simply deleted with no additional logic.

Concluding the store instruction request generation, a memory-order violation check takes place: all loads in the LSQ are searched in ascending age order to see if their addresses overlap with the store. If any are discovered, a flush is triggered to re-execute the invalid load instruction and everything after it. 

Ticking
*******

The LSQ is expected to be ticked once per clock cycle. This tick is used to select requests from the ``requestQueue_``, handle responses to memory read requests, and finish execution of completed load instructions.

Request selection
    Requests are removed from the ``requestQueue_`` in a queue-like fashion and processed. Adherence to model defined restrictions, such as the per cycles bandwidth or the number of store/load requests permitted per cycle, are maintained during removal.

Handling responses
    The memory interface is scanned for completed read requests. If any are present, the relevant load instruction is found and the data supplied, marking the load as complete.

Finishing execution
    Depending on the number of completion slots available, completed load instructions are identified and executed to arrange the loaded data into the output register format, before writing the instructions into the completion slots.

