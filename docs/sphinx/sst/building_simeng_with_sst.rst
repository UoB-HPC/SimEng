Building SimEng with SST
========================

Prerequisites
*************
In addition to CMake and a compiler that supports C++17, version **12.0.x** of SST-Core and SST-Elements are required.

.. warning::
    Please ensure that while installing SST-Elements, the initial configuration step should include the
    ``--with-sst-core=<sst-core_install_directory>`` flag so that all components present in **SST-Elements** are registered with the **SST-Core**.
    This is important because **SimEng** relies on components present in **SST-Elements**. 
    However, if these components aren't registered, **SST-Core** will fail to locate the components to use during simulation.

.. note::
    If the path: ``<sst-core_install_directory>/bin`` is added to the ``$PATH`` environment variable then all sst executables will be 
    available globally. i.e. you will be to use the commands ``sst`` , ``sst-info``, ``sst-register`` and ``sst-config`` without having to navigate
    to the SST install directory.

Build Steps
***********
Two flags have been added to SimEng's CMake configuration step to enable integration with SST:

.. code-block:: text

       -DSIMENG_ENABLE_SST={ON, OFF} // Defaults to OFF
       -DSST_INSTALL_DIR=<sst-core_install_directory> // Path to the SST-Core install location

The rest of the steps for building and installing SimEng with SST integration remain the same as a standalone SimEng :ref:`installation<Building_SimEng>` i.e the build step and the install step.

Validation
**********
A successful SST installation should also install the ``sst-info`` executable. This executable is used to print all the components registered with SST-Core which
can be used in an SST simulation. To verify a successful installation of SimEng with SST integration enabled, the command ``sst-info --libs=libsstsimeng``  
should output:

.. code-block:: text

    ================================================================================
    ELEMENT 0 = sstsimeng()
    Num Components = 1
        Component 0: simengcore
        CATEGORY: PROCESSOR COMPONENT
            NUM STATISTICS = 0
            NUM PORTS = 0
            NUM SUBCOMPONENT SLOTS = 0
            NUM PARAMETERS = 5
                PARAMETER 0 = config_path (Path to Simeng YAML config file (string)) []
                PARAMETER 1 = executable_path (Path to executable binary to be run by SimEng (string)) []
                PARAMETER 2 = executable_args (argument to be passed to the executable binary (string)) []
                PARAMETER 3 = clock (Clock rate of the SST clock (string)) []
                PARAMETER 4 = max_addr_memory (Maximum address that memory can access (int)) [<required>]
        simengcore: Simeng core wrapper for SST
        Using ELI version 0.9.0
        Compiled on: Aug 25 2022 11:55:05, using file: <path_to_simeng>/sst/include/SimengCoreWrapper.hh
    Num SubComponents = 0
    Num Modules = 0
    Num SSTPartitioners = 0
