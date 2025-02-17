Running SimEng
==============

SimEng uses a configuration file and a program binary to produce a cycle-accurate simulation of a modern processor. These options are passed to SimEng through the following command line arguments: 

.. code-block:: text

        <simeng_install_directory>/bin/simeng <config file> <binary>

If no arguments are passed to SimEng, default options are used. The default configuration file is tuned to a ThunderX2 processor. The default program is a binary compiled to AArch64 found at ``SimEng/SimEngDefaultProgram``. This prints a welcome message to the console.

Whilst a configuration file can be specified without a program (will use default program), a specified program must be accompanied by a configuration file.

Simulation Output
-----------------

For a successful simulation, SimEng's output can be split into 4 parts;

Build Metadata
    A summary of the build options set and general information about the SimEng framework built.

Workload Output
    All outputs from the supplied workload under simulation.

Exit Clause
    The reason why the simulation has halted. Most commonly this is due to the invoking of the ``exit()`` system call by the workload under simulation.

Statistics
    A selection of simulation statistics describing the emergent simulated PMU-style hardware events. With respect to branch statistics, the misprediction rate
is calculated as branches mispredicted / branches retired.

All non-workload outputs from SimEng are prefixed with a tag of the format ``[SimEng:Object]`` (e.g. ``[SimEng:ExceptionHandler]``). If the output came from the root of the framework, the ``Object`` field is omitted.

Configuration files
-------------------

SimEng provides several configuration files that parameterise the simulated model. These can be found in ``<simeng_repository>/configs`` and more information about their content can be found :doc:`here <configuring_simeng>`.

The following examples illustrate the use of both the ThunderX2 and A64FX configurations:

ThunderX2 processor
        ``<simeng_install_directory>/bin/simeng <simeng_repository>/configs/tx2.yaml <binary>``

A64FX processor
        ``<simeng_install_directory>/bin/simeng <simeng_repository>/configs/a64fx.yaml <binary>``

