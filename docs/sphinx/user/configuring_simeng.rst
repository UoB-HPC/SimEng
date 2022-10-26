.. _cnfSimEng:

Configuring SimEng
==================

SimEng configuration files are written in a YAML format, and provide values for the parameters of the processor architecture to be simulated. Pre-written model configuration files can be found in the ``configs/`` directory.

The configuration files are split into several sections, each of which is associated with a specific area of the architecture modelled.

.. _core:
Core
----

SimEng cores can be one of three types: 

``emulation``
    An atomic "emulation-style" core which, per cycle, processes an instruction in its entirety before proceeding to the next instruction.

``inorderpipeline``
    An in-order pipeline processor core with discrete fetch, decode, execute, and writeback stages.

``outoforder``
    A complex superscalar out-of-order core, similar to those found in modern high-performance processors.

These core types are primarily referred to as core "archetypes".

.. Note:: Currently, the configuration files do not take into account the core archetype being modelled and require all parameters (without default values) to be defined, even if unused (e.g. reservation station definitions for an ``emulation`` core archetype). However, future developments plan for the exemption of those options not used under the selected core archetype.

Configuration options within the Core section are concerned with the functionality of the simulated processor pipeline. These include:

Simulation-Mode
    The core archetype to use, the options are ``emulation``, ``inorderpipelined``, and ``outoforder``.

Clock-Frequency
    The clock frequency, in GHz, of the processor being modelled.

Timer Frequency
    This dictates the frequency in MHz that the CPU's internal counter timer is updated. 

    i.e. For models based on an Arm ISA, this dictates how often the Virtual Counter Timer system register is updated to the number of cycles completed. This value is then accessible to programmers through ``mrs x0 CNTVCT_el0``.

Micro-Operations
    Whether to enable instruction splitting for pre-defined Macro Operations or not.

Vector-Length
    The vector length used by instructions belonging to Arm's Scalable Vector Extension. Supported vector lengths are those between 128 and 2048 in increments of 128.

Streaming-Vector-Length
    The vector length used by instructions belonging to Arm's Scalable Matrix Extension. Although the architecturally valid vector lengths are powers of 2 between 128 and 2048 inclusive, the supported vector lengths are those between 128 and 2048 in increments of 128.

Fetch
-----

This section is concerned with the parameterisation of the fetch unit and its internal structures.

Fetch-Block-Size
    The size, in bytes, of the block fetched from the instruction cache.

Loop-Buffer-Size
    The number of Macro-ops which can be stored in the loop buffer.

Loop-Detection-Threshold
    The number of commits a unique branch instruction must go through, without another branch instruction being committed, before a loop is detected and the loop buffer is filled.

Process Image
-------------

This allows the stack and heap size to be altered as required.

Heap-Size
    Size of the Heap; defined in bytes.

Stack- Size 
    Size of the Stack in memory; defined in bytes.

Register-set
------------

The number of physical registers, of each type, to be used under the register renaming scheme. These types include:

GeneralPurpose-Count
    The number of physical general-purpose registers.

FloatingPoint/SVE-Count
    The number of physical floating point registers. Also considered as the number of Arm SVE extension ``z`` registers where appropriate.

Predicate-Count (Optional)
    The number of physical Arm SVE extension predicate registers.

Conditional-Count
    The number of physical status/flag/conditional-code registers.

MatrixRow-Count
    The number of physical rows for SME's ``za`` register. SimEng's implementation of the ``za`` matrix register treats each row as a vector register. Having the MatrixRow-Count equal to the Streaming-Vector-Length/8 will yield a single physical ``za`` register. As such, the MatrixRow-Count must be a minimum of Streaming-Vector-Length/8.

Pipeline-widths
---------------

This section is concerned with the width of the simulated processor pipeline at specific stages, including:

Commit
    The commitment/retirement width from the re-order buffer.

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

BTB-Tag-Bits
    The number of bits used to denote an entry in the Branch Target Buffer (BTB). For example, a ``bits`` value of 12 could denote 4096 entries with the calculation 1 << ``bits``.

Saturating-Count-Bits
    The number of bits used in the saturating counter value.

Global-History-Length
    The number of bits used to record the global history of branch directions. Each bit represents one branch direction.

RAS-entries
    The number of entries in the Return Address Stack (RAS).

Fallback-Static-Predictor
    The static predictor used when no dynamic prediction is available. The options are either ``"Always-Taken"`` or ``"Always-Not-Taken"``.

.. _l1dcnf:

L1-Data-Memory
--------------

This section describes the configuration for the L1 data cache in use.

Interface-Type
    The type of memory interface used to model the L1 data cache. Options are currently ``Flat`` or ``Fixed`` which represent a ``FlatMemoryInterface`` or ``FixedMemoryInterface`` respectively. More information concerning these interfaces can be found :ref:`here <memInt>`.

.. Note:: Currently, if the chosen ``Simulation-Mode`` option is ``emulation`` or ``inorderpipelined``, then only a ``Flat`` value is permitted. Future developments will seek to allow for more memory interfaces with these simulation archetypes.

.. _l1icnf:

L1-Instruction-Memory
---------------------

This section describes the configuration for the L1 instruction cache in use.

Interface-Type
    The type of memory interface used to model the L1 instruction cache. Options are currently ``Flat`` or ``Fixed`` which represent a ``FlatMemoryInterface`` or ``FixedMemoryInterface`` respectively. More information concerning these interfaces can be found :ref:`here <memInt>`.

.. Note:: Currently, only a ``Flat`` value is permitted for the L1 instruction cache interface. Future developments will seek to allow for more memory interfaces to be used with the L1 instruction cache.

LSQ-L1-Interface
----------------

This section contains the options used to configure SimEng's interface between the LSQ and the L1 data cache. These options include:

Access-Latency
    The cycle latency of L1 cache access.

Exclusive
    If set to true, only one type of memeory access (read or write) can be performed per cycle.

Load-Bandwidth
    The number of bytes permitted to be loaded per cycle.

Store-Bandwidth
    The number of bytes permitted to be stored per cycle.

Permitted-Requests-Per-Cycle
    The number of load and store requests permitted per cycle.

Permitted-Loads-Per-Cycle
    The number of load requests permitted per cycle.

Permitted-Stores-Per-Cycle
    The number of store requests permitted per cycle.

.. _execution-ports:

Ports
-----

Within this section, execution unit port definitions are constructed. Each port is defined with a name and a set of instruction groups it supports. The instruction groups are architecture-dependent, but, the available AArch64 instruction groups can be found :ref:`here <aarch64-instruction-groups>`.

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

The relationships between reservation stations and the execution ports, i.e. which reservation stations map to which execution ports, are defined in this section. The configuration of each reservation station contains a size value, a dispatch rate value, and a set of port names, previously defined in the Ports section. 

The following structure must be adhered to when defining a reservation station:

.. code-block:: text

    0:
      Size: <number_of_entries>
      Dispatch-Rate: <number_of_permitted_dispatches_per_cycle>
      Ports:
      - <port_name>
      - ...
      - <port_name>
    ...
    N-1:
        Size: <number_of_entries>
        Dispatch-Rate: <number_of_permitted_dispatches_per_cycle>
        Ports:
        - <port_name>
        - ...
        - <port_name>

With N as the number of reservation stations. Each execution port must be mapped to a reservation station.


Execution-Units
---------------

An execution unit can be configured to optionally include an internal pipeline and a set of instruction groups for :ref:`operation blocking <operation-blocking>`. The instruction groups referenced here are the same as those used in the Ports section.

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

.. _config-latencies:

Latencies
---------

The execution latency and throughput can be configured under the Latencies section. A latency/throughput pair can be defined for a set of instruction groups, the groups available are the same as the set discussed in the Ports section.

The execution latency defines the total number of cycles an instruction will spend in an execution unit. The throughput is how many cycles an instruction will block another instruction entering the execution unit. In non-pipelined execution units, the throughput is equal to the latency.

The following structure must be adhered to when defining group latencies:

.. code-block:: text

    0:
      Instruction-Groups:
      - <instruction_group>
      - ...
      - <instruction_group>
      Execution-Latency: <number_of_cycles>
      Execution-Throughput: <number_of_cycles>
    ...
    N-1:
        Instruction-Groups:
        - <instruction_group>
        - ...
        - <instruction_group>
        Execution-Latency: <number_of_cycles>
        Execution-Throughput: <number_of_cycles>

With N as the number of user-defined latency mappings. The default latencies, both execution and throughput, for those instruction groups not covered are 1.

**Note**, unlike other operations, the execution latency defined for load/store operations are triggered in the LoadStoreQueue as opposed to within the execution unit (more details :ref:`here <lsq-restrict>`).

.. _cpu-info:

CPU Info
--------
    This section contains information about the physical properties of the CPU.
    These fields are currently only used to generate a replica of the required Special Files directory structure.

Generate-Special-Dir
    Values are either "True" or "False".
    Dictates whether or not SimEng should generate the SpecialFiles directory tree at runtime.
    The alternative to this would be to copy in the required SpecialFiles by hand.

Core-Count
    Defines the total number of Physical cores (Not including threads).

.. Note:: Max Core-Count currently supported is 1.

Socket-Count
    Defines the number of sockets used. Typically set to 1, but can be more for CPU's that support multi-socket implementations (i.e. ThunderX2).

.. Note:: Max Socket-Count currently supported is 1.
.. Note:: If Socket-Count is more than 1, Core-Count must reflect the number of physical cores per socket.

SMT
    Defines the number of threads present on each core.

.. Note:: Max SMT currently supported is 1.

The fields listed below are used to generate `/proc/cpuinfo`. Their values can be found there on a Linux system using the CPU being modelled. With each field is a description of the format required and an example value.

    - BogoMIPS : Float in format `x.00`, i.e. `200.00`
    - Features : String with values seperated with a space, i.e. `"fp asimd sha1 sha2 fphp"`
    - CPU-Implementer : Hex value represented as a string, i.e. `"0x46"`
    - CPU-Architecture : Integer, i.e. `8`
    - CPU-Variant : Hex value represented as a string, i.e. `"0x1"`
    - CPU-Part : Hex value represented as a string, i.e. `"0x001"`
    - CPU-Revision : Integer, i.e. `0`

.. Note:: If values are unknown then set equal to 0 in the correct format

Package-Count
    Used to generate `/sys/devices/system/cpu/cpu{0..Core-Count}/topology/{physical_package_id, core_id}` files.
    On each CPU the cores are split into packages. The number of packages used can be calculated by analysing the `physical_package_id` files on a Linux system using the CPU being modelled.

.. Note:: Core-Count must be wholly divisible by Package-Count.
.. Note:: Max Package-Count currently supported is 1.
