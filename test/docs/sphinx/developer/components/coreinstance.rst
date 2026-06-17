Core Instance
=============

The ``CoreInstance`` component supplies the functionality for instantiating all simulation objects and linking them together.

The standard process taken to create an instance of the modelled core is as follows:

Process the config file
    Either the passed configuration file path, or default configuration string, is used to generate the model configuration class. All subsequent parameterised instantiations of simulation objects utilise this configuration class.

Create the image process
    From the passed workload path, or default set of instructions, a process image is created. A region of host memory is populated with workload data (e.g. instructions), a region for the HEAP, and an initial stack frame. References to it are then passed between various simulation objects to serve as the underlying process memory space.

Construct on-chip cache interfaces
    Based on the supplied configuration options, the on-chip cache interfaces are constructed. These interfaces sit on top of a reference to the process memory space constructed prior. Currently, only L1 instruction and data caches are supported and the interfaces are defined under the :ref:`L1-Data-Memory <l1dcnf>` and  :ref:`L1-Instruction-Memory <l1icnf>` config options.

Construct the core simulation object 
    After all the general components are created, the simulated core object is constructed. The architecture, branch predictor, and issue port allocator are first constructed and subsequently passed to the core object. Within the core object itself, relevant simulation objects are constructed using the instantiations carried out in the ``CoreInstance`` class. The exact simulation objects created are dependent on the core :ref:`archetype <archetypes>` in use.

Special File Directory
    Finally, SimEng's special file directory is constructed if enabled within the passed configuration. More information about its usage can be found :ref:`here <specialDir>`.

The ``CoreInstance`` class also contains a selection of getter functions for obtaining information about the simulation objects constructed.