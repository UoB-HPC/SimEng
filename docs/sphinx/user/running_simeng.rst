Running SimEng
==============

SimEng uses a configuration file and a program binary to produce a cycle-accurate simulation of a modern processor. These options are passed to SimEng through the following command line arguments: 

.. code-block:: text

        <simeng_install_directory>/bin/simeng <config file> <binary>

If no arguments are passed to SimEng, default options are used. The default configuration file is tuned to a ThunderX2 processor, and the default program binary is defined in ``src/tools/simeng/main.cc`` under the ``hex[]`` array.

.. Note:: Paths to binaries must be in full, and not relative.

Whilst a configuration file can be specified without a program (will use default program), a specified program must be accompanied by a configuration file.

Configuration files
-------------------

SimEng provides several configuration files that parameterise the simulated model. These can be found in ``<simeng_repository>/configs`` and more information about their content can be found :doc:`here <configuring_simeng>`.

The following examples illustrate the use of both the ThunderX2 and A64FX configurations:

ThunderX2 processor
        ``<simeng_install_directory>/bin/simeng <simeng_repository>/configs/tx2.yaml <binary>``

A64FX processor
        ``<simeng_install_directory>/bin/simeng <simeng_repository>/configs/a64fx.yaml <binary>``

