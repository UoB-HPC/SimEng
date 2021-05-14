Configuring SimEng
==================

SimEng configuration files are written in a YAML format, and provide values for the parameters of the processor architecture to be simulated. 

Currently, the configuration files do not take into account the core archetype being modelled. However, future developments plan for the exemption of those options not used under the selected core archetype. For example, reservation station definitions under the ``inorderpiplined`` archetype will not be required.

The configuration files are split into several sections, each of which is associated with a specific area of the architecture modelled.

Core
----

Configuration options within the Core section are concerned with the functionality of the simulated processor pipeline. These include:

Simulation-Mode
    The core archetype to use, the options are ``emulation``, ``inorderpipelined``, and ``outoforder``.

Clock-Frequency
    The clock frequency, in GHz, of the processor being modelled.

Fetch-Block-sizes
    The size, in bytes, of the block fetched from the instruction cache.

.. - Vector-Length

Register-set
------------

The number of physical registers, of each type, to be used under the register renaming scheme. These types include:

GeneralPurpose-Count
    The number of physical general-purpose registers.

FloatingPoint/SVE-Count
    The number of physical floating point registers. Also considered as the number of ARM SVE extension ``z`` registers where appropriate.

Predicate-Count (Optional)
    The number of physical ARM SVE extension predicate registers.

Conditional-Count
    The number of physical status/flag/conditional-code registers.

Pipeline-widths
---------------

This section is concerned with the width of the simulated processor pipeline at specific stages, including:

Commit
    The commitment/retirement width from the re-order buffer.

Dispatch-Rate
    The width of instruction dispatch into the reservation stations.

FrontEnd
    The width of the pipeline before the execution stage (also excludes the dispatch/issue stage if simulating an ``outoforder`` core archetype).

LSQ-Completion
    The width between the load/store queue unit and the write-back unit (translates to the number of load instructions that can be sent to the write-back unit per cycle).

Excluding the Commit option, the value given for these widths denotes the number of Micro-Ops, as opposed to Macro-ops, if the simulated architecture supports them.

Queue-sizes
-----------

This section defines the size of specific architectural queues. These queues currently include:

ROB
    The size of the re-order buffer.

Load
    The size of the load queue within the load/store queue unit.

Store
    The size of the store queue within the load/store queue unit.


Branch-Predictor
----------------

The Branch-Prediction section contains those options to parameterise the branch predictor used during simulation. Currently, the options are minimal, but, planned developments will see options including the toggling and parameterisation of common branch predictor algorithms/structures.

The current options include:

BTB-bitlength
    The number of bits used to denote the size of a Branch Target Buffer (BTB). For example, a ``bits`` value of 12 would denote 4096 entries with the calculation 1 << ``bits``.

L1-Cache
--------

This section contains the options used to configure SimEng's simple L1-cache. These options include:

GeneralPurpose-Latency
    The cycle latency of integer load/store operations.

FloatingPoint-Latency
    The cycle latency of floating point load/store operations.

SVE-Latency (Optional)
    The cycle latency of ARM SVE extension load/store operations.

Bandwidth
    The number of bytes permitted to be loaded and/or stored per cycle.

Permitted-Requests-Per-Cycle
    The number of load and store requests permitted per cycle.

Permitted-Loads-Per-Cycle
    The number of load requests permitted per cycle.

Permitted-Stores-Per-Cycle
    The number of store requests permitted per cycle.

Ports
-----

Within this section, execution unit port definitions are constructed. Each port is defined with a name and a set of instruction groups it supports. The instruction groups are architecture-dependent but, for the supported AArch64 ISA, the instruction groups available include:

- ``INT_ARTH``. All integer arithmetic operations excluding multiply, divide, and square root.
- ``INT_ARTH_NOSHIFT``. A subset of ``INT_ARTH`` excluding all operations containing a shift operand.
- ``INT_MUL``. Integer multiply operations.
- ``INT_DIV_OR_SQRT``. Integer divide or square root operations.
- ``FLOAT_ARTH``. All floating point arithmetic operations excluding multiply, divide, and square root. 
- ``FLOAT_ARTH_NOSHIFT``. A subset of ``FLOAT_ARTH`` excluding all operations containing a shift operand. 
- ``FLOAT_MUL``. Floating point multiply operations. 
- ``FLOAT_DIV_OR_SQRT``. Floating point divide or square root operations. 
- ``LOAD``. All load operations.
- ``STORE``. All store operations.
- ``BRANCH``. All branch operations.
- ``PREDICATE``. All ARM SVE extension instructions that write to a predicate register.

To define a port, the following structure must be adhered to:

.. code-block:: text

    0:
      Portname: <port_name>
      Instruction-Support:
      - <instruction_group>
      - ...
      - <instruction_group>
    ...
    N-1:
        Portname: <port_name>
        Instruction-Support:
        - <instruction_group>
        - ...
        - <instruction_group>

With N as the number of execution ports.

Reservation-Stations
--------------------

The relationships between reservation stations and the execution ports, which reservation stations map to which execution ports, are defined in this section. The configuration of each reservation station contains a size value and a set of port names, previously defined in the Ports section. 

The following structure must be adhered to when defining a reservation station:

.. code-block:: text

    0:
      Size: <number_of_entries>
      Ports:
      - <port_name>
      - ...
      - <port_name>
    ...
    N-1:
        Size: <number_of_entries>
        Ports:
        - <port_name>
        - ...
        - <port_name>

With N as the number of reservation stations. Each execution port must be mapped to a reservation station.


Execution-Units
---------------

An execution unit can be configured to optionally include an internal pipeline and a set of instruction groups for :ref:`operation blocking <operation-blocking>`). The instruction groups referenced here are the same as those used in the Ports section.

The following structure must be adhered to when defining an execution unit:

.. code-block:: text

    0:
      Pipelined: <True/False>
      Blocking-Groups:
      - <instruction_group>
      - ...
      - <instruction_group>
    ...
    N-1:
        Pipelined: <True/False>
        Blocking-Groups:
        - <instruction_group>
        - ...
        - <instruction_group>

With N as the number of execution units. The number of execution units should be equivalent to the number of execution ports.

**Note**, the indexing used in both the Ports and Execution-Units sections provide a relationship mapping, the 0th execution port maps to the 0th execution unit.