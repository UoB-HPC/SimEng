# SimEng

TODO: Add summary of project, links to docs etc.

## Building

Building SimEng requires CMake and a compiler that supports C++17.

First obtain the source code using git, including the dependencies:
1. If cloning for the first time, use the `--recurse-submodules` option:
```bash
git clone --recurse-submodules https://github.com/UoB-HPC/SimEng.git
```
2. If you already have a clone, update the source and submodules:
```bash
git pull origin master
git submodule update --init
```

Configure with CMake, specifying the path to your desired installation directory if necessary:

    cmake <path_to_simeng_source>                           \
          -DCMAKE_BUILD_TYPE=Release                        \
          -DCMAKE_INSTALL_PREFIX=<target_install_directory>

Once configured, use `make` (or your preferred build tool) to build.

Run `make test` to run the SimEng regression tests and unit tests.
Please report any test failures as [a GitHub issue](https://github.com/UoB-HPC/SimEng/issues).

Finally, run `make install` to install SimEng to the directory specified to CMake.
