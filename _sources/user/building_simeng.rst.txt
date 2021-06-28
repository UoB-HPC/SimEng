Building SimEng
===============

Prerequisites
-------------

Building SimEng requires CMake and a compiler that supports C++17.

Building
--------

1. Obtain the source code using git:
   
.. code-block:: text

        git clone https://github.com/UoB-HPC/SimEng.git


2. Configure with CMake, specifying the path to your desired installation directory if necessary::

        cd SimEng
        cmake -B build -S . # build files will be generated in a directory called "build"
                -DCMAKE_BUILD_TYPE=Release                        
                -DCMAKE_INSTALL_PREFIX=<simeng_install_directory>
                -DSIMENG_ENABLE_TESTS={ON, OFF} # Defaults to OFF
                # -GNinja # enable Ninja for faster LLVM builds

..

        a. The SimEng test suites depend on a selection of LLVM libraries. Building this dependency can take a while, therefore, the use of prebuilt LLVM libraries is supported. The following cmake configuration flags should be set to enable this::
                
                -DSIMENG_USE_EXTERNAL_LLVM=ON
                -DLLVM_DIR=<llvm_library_directory> # directory of LLVM libraries as CMake targets

        .. Note::
                More information about the LLVM_DIR value can be found `here <https://llvm.org/docs/CMake.html#embedding-llvm-in-your-project>`_.
        
3. Once configured, use ``cmake --build build`` or whichever generator you have selected for CMake to build. Append the ``-j`` flag to build in parallel, keep in mind that building LLVM like this usually has very high (1.5GB per core) memory requirements.

4. (Optional) Run ``cmake --build build --target test`` to run the SimEng regression tests and unit tests. Please report any test failures as `a GitHub issue <https://github.com/UoB-HPC/SimEng/issues>`_.

5. Finally, run ``cmake --build build --target install`` to install SimEng to the directory specified with CMake.


Docker
------

We have also created a SimEng docker container, offering pre-built images with the SimEng source code and binary. More details on the docker container can be found :doc:`here<docker>`.

