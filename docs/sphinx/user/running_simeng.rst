Running SimEng
==============

Configuration files
-------------------

SimEng provides several configuration files that can be found in ``<simeng_repository>/configs``. These files specify the architecture you are simulating, for example,  ``Simulation-Mode``, ``Clock-Frequency``, ``Register-Set``, etc.


Running SimEng with Hardcoded Instructions
------------------------------------------

1. SimEng uses a configuration and a program to produce a cycle-accurate simulation of a modern processor, these arguments can be specified at the command line. By default, the configuration is based on a ThunderX2 processor and the binary is located in the ``hex[]`` array, ``src/tools/simeng/main.cc``. 

2. To run SimEng with a custom configuration file or prebuilt binary, add these arguments to the command line (Example binaries can be found in ``<simeng_repository>/binaries``)

.. code-block:: text

        <simeng_install_directory>/bin/simeng <config file> <binary>

NOTE: Paths to config files and binaries must be in full, and not relative.