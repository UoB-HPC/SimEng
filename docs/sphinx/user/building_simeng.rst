Building SimEng
===============

Prerequisites
-------------

Building SimEng requires CMake and a compiler that supports C++17. 

(Optional) Docker, see our Docker instructions `here <https://uob-hpc.github.io/SimEng-Docs/docker.html>`_.

Building
--------

First obtain the source code using git, including the dependencies:

1. If cloning for the first time, use the ``--recurse-submodules`` option:
   
.. code-block:: text

        git clone --recurse-submodules https://github.com/UoB-HPC/SimEng.git

2. If you already have a clone, update the source and submodules:
   
.. code-block:: text

        git pull origin master
        git submodule update --init

3. Configure with CMake, specifying the path to your desired installation directory if necessary:
   
.. code-block:: text

        cmake <path_to_simeng_repository>                       
                -DCMAKE_BUILD_TYPE=Release                        
                -DCMAKE_INSTALL_PREFIX=<simeng_install_directory>

E.G:

.. code-block:: text

        cd SimEng
        mkdir install && cd install
        cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD

4. Once configured, use ``make`` (or your preferred build tool) to build.

5. (Optional) Run ``make test`` to run the SimEng regression tests and unit tests. Please report any test failures as `a GitHub issue <https://github.com/UoB-HPC/SimEng/issues>`_.

6. Finally, run ``make install`` to install SimEng to the directory specified to CMake.

