Running SimEng
==============

Configuration files
-------------------

SimEng provides several configuration files that can be found in ``<simeng_repository>/configs``. These files specify the architecture you are simulating, for example,  ``Simulation-Mode``, ``Clock-Frequency``, ``Register-Set``, etc.


Running SimEng with Hardcoded Instructions
------------------------------------------

1. SimEng needs a configuration file and a program to produce a cycle-accurate simulation of a modern processor, these arguments are specified at the command line. NOTE: Paths to config files and binaries must be in full, and not relative.


2. SimEng comes with several hardcoded programs that can be run straight out of the box, these are located in the ``hex[]`` array, ``src/tools/simeng/main.cc``. To run these simple programs, just specify the configuration file at the command line.
::
        <simeng_install_directory>/bin/simeng <config file>

3. To run SimEng with a prebuilt binary, just add the binary path as the 2nd argument. Example binaries can be found in ``<simeng_repository>/binaries``.
::
        <simeng_install_directory>/bin/simeng <config file> <binary>