.. _instructions:

Instructions
============

An instruction represents a discrete operation that a processor may perform. Instructions are independent objects that have no direct access to registers/memory, and must be supplied values to operate on by the model.

Lifecycle
---------

To permit instructions to function independently of the type of model they exist within, the lifetime of each instruction is broken down into a sequence of stages.

Post-Decode
***********
This is the initial step of an instruction. At this stage, the instruction has been fully decoded and is now capable of advertising the registers it reads and writes, as well as various metadata such as whether it's a load, store, or branch, and which architecture-specific instruction group it belongs to. The model can use this information to supply the instruction with the appropriate values for each source operand, and determine where the instruction should be sent for processing.

Ready to execute
****************
Once an instruction has received all of the necessary input values, it becomes ready to execute. At this stage, the model may request that the instruction generates addresses (loads and stores only) or that it executes.

Address generation
******************
(Loads and stores only).
If an instruction has reported itself as a load or store, once ready to execute it will be instructed to generate the set of addresses it will access. While stores may execute immediately, loads are considered pending until the model supplies a corresponding piece of data for each generated address, and may only execute once all data is available.

Executed
********
Executing an instruction performs the relevant operation using the input values, and makes the results available to the model, along with the registers these results should be written to. As instructions have no access to memory, the execution step for stores is expected to produce a corresponding piece of data to write to each address generated, using the input values supplied; these address/data pairs are presented to the model for writing to memory. For branches, the calculated address will also be available.

.. _macroops:

Macro-Ops
---------

A SimEng instruction represents what are typically referred to as "micro-ops" (also known as µops or uops): a single conceptual hardware operation. To support more complex instruction sets where individual instructions perform multiple operations, some SimEng components deal with "macro-ops", which are conceptual objects that may be split into a stream of SimEng ``Instruction`` objects. As a result, individual machine-code instructions may become multiple SimEng ``Instruction`` objects when processed.
