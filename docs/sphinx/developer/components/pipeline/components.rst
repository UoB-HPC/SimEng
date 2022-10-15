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

.. _microOpCommit:

commitMicroOps
**************

When a macro-op is split, all created micro-ops can only be committed when all are ready to do so. These micro-ops firstly enter a "waiting commit" state and once all associated micro-ops are in said state, they can then enter a "ready to commit" state and commit in the standard manner. The ``commitMicroOps`` function facilitates this state transition whilst the ``WritebackUnit`` sets the "waiting commit" state.

.. _loopDetect:

Loop detection
**************

For the loop buffer to operate within the fetch unit (detailed :ref:`here <loopBuf>`) the detection of loops, and the branches which represent them, must be facilitated. The ROB supports this functionality by tracking the retirement of branch instructions. If the same branch instruction retires a configurable number of times, with the same target and direction, then a loop is detected. No other branch or different outcomes from the same branch can be retired within this period.

LoadStoreQueue
--------------

The ``LoadStoreQueue`` class models the load/store queue (LSQ) common to many out-of-order architectures. This structure contains in-order references to all in-flight load and store instructions, in a ``loadQueue_`` and ``storeQueue_`` respectively, which it uses to ensure memory operations occur in program order.

To accommodate multiple varieties of LSQ, this model provides two modes: **split**, representing an LSQ with two discrete independently sized queues for holding loads and stores respectively, and **combined**, representing an LSQ with a single shared queue that holds both loads and stores.

.. Todo::
    Allow for combined option to be defined via configuration files.

.. _lsq-restrict:

To enforce restrictions such as the number of loads/stores requests permitted per cycle, secondary request queues, ``requestLoadQueue_`` and ``requestStoreQueue_``, are utilised. These queues hold all distinct requests made by in-flight loads and stores with each entry being a ``requestEntry`` struct, containing a queue of addresses to access and the instruction performing the requests. Additionally, the entries in this queue can only be processed after a defined number of cycles. This value is the pre-defined latency for a memory operation beyond that of the fixed L1 cache access latency. An internal clock is used to facilitate this delayed removal from the queues and requests are grouped by such clock cycles within the queues themselves.

All load and store instructions should be added to the LSQ in program order; this typically happens during the last in-order stage of an out-of-order model. In the default SimEng pipeline units, ``RenameUnit`` performs this task.

Loads
*****

When initially added to the LSQ, loads are considered pending: they exist primarily to hold their place in the load queue, and aren't considered for memory order logic.

Once the addresses have been calculated for the load, the LSQ should be informed that the load operation can now be started. At this point, each address has two outcomes, either generate a request to be sent to the memory interface or wait until a store that conflicts with the access is retired. If a conflict is detected between an active store and the current load, the address is placed into a ``conflictionMap_``. Once the store retires, the data will be forwarded to the load and will resume operation as if the initial request for that address had been completed. A conflict is found if the youngest (program order) active store with the same address accessed is storing data of size equal to or greater than that read by the load. If no conflict is found for the address, a ``requestEntry`` is generated and placed into the ``requestLoadQueue_``. Once an entry is selected in the ``requestLoadQueue_``, the LSQ will send the required data over the memory interface as a read request. When these requests receive responses, during a later cycle, the data will be passed to the relevant load instruction. Once all data has been received, the load is flagged as complete.

Once a completion slot is available, the load will be executed, the results broadcast to the supplied operand-forwarding handle, and the load instruction written into the completion slot. The load instruction will remain in the load queue until it commits.


.. _store-retire:

Stores
******

As with loads, stores are considered pending when initially added to the LSQ. Whilst like load operations the generation of addresses to be accessed must occur before commitment, an additional operation of supplying the data to be stored must also occur. The ``supplyStoreData`` function facilitates this by placing the data to be stored within the ``storeQueue_`` entry of the associated store. Once the store is committed, the data is taken from the ``storeQueue_`` entry.

The generation of store instruction write requests are carried out after its commitment. The reasoning for this design decision is as followed. With SimEng supporting speculative execution, processed store instruction may come from an incorrectly speculated branch direction and will inevitably be removed from the pipeline. Therefore, it is important to ensure any write requests are valid, concerning speculative execution, as the performance cost of reversing a completed write request is high.

Store write requests are placed into the ``requestStoreQueue_`` similar to load read requests. Unlike load instructions read requests, the write requests are submitted to the memory interface before being selected from the ``requestStoreQueue_``. Since store instruction write requests are appended to the ``requestStoreQueue_`` after their commitment, we can be confident that the data to be stored and the order in which it is occurring is correct.

To minimise simulation errors, write requests are sent to the memory interface early. These errors are derived from write requests occurring too late after a store instruction's commitment. Rarely, such latencies cause following load instructions to read incorrect data.

Although the write request has been submitted, it continues to occupy an entry in the ``requestStoreQueue_`` to simulate the contention of LSQ resources between load and store operations (e.g. the number of permitted requests per cycle). Once selected from the ``requestStoreQueue_``, the write request is simply deleted with no additional logic.

Concluding the store instruction request generation, a memory-order violation check takes place: all loads in the LSQ are searched in ascending age order to see if their addresses overlap with the store. If any are discovered, a flush is triggered to re-execute the invalid load instruction and everything after it. Additionally, it is at this point that any conflict between the store and loads is resolved through the forwarding of the data being stored.

Ticking
*******

The LSQ is expected to be ticked once per clock cycle. This tick is used to select requests from the ``requestLoadQueue_`` and/or ``requestStoreQueue_``, handle responses to memory read requests, and finish the execution of completed load instructions.

Request selection
    Requests are removed from the ``requestLoadQueue_`` and/or ``requestStoreQueue_`` in a queue-like fashion and processed. The selection of a load or a store is based on which request is ready earlier with the result of a tie favouring the store operation. Adherence to model defined restrictions, such as the per cycles bandwidth or the number of store/load requests permitted per cycle, are maintained during removal.

Handling responses
    The memory interface is scanned for completed read requests. If any are present, the relevant load instruction is found and the data supplied, marking the load as complete.

Finishing execution
    Depending on the number of completion slots available, completed load instructions are identified and executed to arrange the loaded data into the output register format, before writing the instructions into the completion slots.

