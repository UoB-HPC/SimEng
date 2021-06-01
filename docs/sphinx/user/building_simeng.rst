Building SimEng
===============

Prerequisites
-------------

Building SimEng requires CMake and a compiler that supports C++17.

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

        cd SimEng
        cmake -B build -S . # build files will be generated in a directory called "build"
                -DCMAKE_BUILD_TYPE=Release                        
                -DCMAKE_INSTALL_PREFIX=<simeng_install_directory>
                # -GNinja # enable Ninja for faster LLVM builds
        
1. Once configured, use ``cmake --build build`` or whichever generator you have selected for CMake to build. Append the ``-j`` flag to build in parallel, keep in mind that building LLVM like this usually has very high (1.5GB per core) memory requirements.

2. (Optional) Run ``cmake --build build --target test`` to run the SimEng regression tests and unit tests. Please report any test failures as `a GitHub issue <https://github.com/UoB-HPC/SimEng/issues>`_.

3. Finally, run ``cmake --build build --target install`` to install SimEng to the directory specified with CMake.


Docker
------

We have also created a SimEng docker container, offering pre-built images with the SimEng source code and binary. More details on the docker container can be found :doc:`here<docker>`.

