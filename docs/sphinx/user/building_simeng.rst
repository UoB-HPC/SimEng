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

.. code-block:: text

        cd SimEng
        cmake -B build -S .
                -DCMAKE_BUILD_TYPE={Release, Debug, RelWithDebInfo, MinSizeRel}
                -DCMAKE_INSTALL_PREFIX=<simeng_install_directory>
                -DSIMENG_ENABLE_TESTS={ON, OFF} #Defaults to OFF

With this configuration, the build files will be generated in a directory called "build".

..

        a. The SimEng test suites depend on a selection of LLVM libraries. Building this dependency can take a while, therefore, the use of prebuilt LLVM libraries is supported. The following CMake configuration flags should be set to enable this::
                
                -DSIMENG_USE_EXTERNAL_LLVM=ON
                -DLLVM_DIR=<llvm_library_directory> # directory of LLVM libraries as CMake targets

        .. Note::
                More information about the LLVM_DIR value can be found `here <https://llvm.org/docs/CMake.html#embedding-llvm-in-your-project>`_.

        .. Note::
                LLVM versions greater than 14 or less than 8 are not supported. We'd recommend using LLVM 14.0.5 where possible as this has been verified by us to work correctly.

        b. Two additional flags are available when building SimEng. Firstly is ``-DSIMENG_SANITIZE={ON, OFF}`` which adds a selection of sanitisation compilation flags (primarily used during the development of the framework). Secondly is ``-SIMENG_OPTIMIZE={ON, OFF}`` which attempts to optimise the framework's compilation for the host machine through a set of compiler flags and options.

We recommend using the `Ninja <https://ninja-build.org/>`_ build system for faster builds, especially if not using pre-built LLVM libraries. After installation, it can be enabled through the addition of the ``-GNinja`` flag in the above CMake build command.

1. Once configured, use ``cmake --build build`` or whichever generator you have selected for CMake to build. Append the ``-j{Num_Cores}`` flag to build in parallel, keep in mind that building without a linked external LLVM library usually has very high (1.5GB per core) memory requirements.

2. (Optional) Run ``cmake --build build --target test`` to run the SimEng regression tests and unit tests. Please report any test failures as `a GitHub issue <https://github.com/UoB-HPC/SimEng/issues>`_.

3. Finally, run ``cmake --build build --target install`` to install SimEng to the directory specified with CMake.

.. Docker
.. ------

.. We have also created a SimEng docker container, offering pre-built images with the SimEng source code and binary. More details on the docker container can be found :doc:`here<docker>`.

