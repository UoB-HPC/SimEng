Running SimEng
==============

SimEng uses a configuration file and a program binary to produce a cycle-accurate simulation of a modern processor, these arguments can be specified at the command line. SimEng offers default options for its command-line arguments, that being a configuration for a ThunderX2 processor and a handwritten program located in the ``hex[]`` array, ``src/tools/simeng/main.cc``. SimEng's command-line options are structured as followed:

.. code-block:: text

        <simeng_install_directory>/bin/simeng <config file> <binary>

**Note**, paths to binaries must be in full, and not relative.

Whilst a configuration file can be specified without a program (will use default program), a specified program must be accompanied by a configuration file.

Configuration files
-------------------

SimEng provides several configuration files that parameterise the simulated model. These can be found in ``<simeng_repository>/configs`` and more information about their content can be found :doc:`here <configuring_simeng>`.