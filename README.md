# SimEng

TODO: Add summary of project, links to docs etc.

## Building

Building SimEng requires CMake and a compiler that supports C++17.

Configure with CMake, specifying the path to your desired installation directory if necessary:

    cmake <path_to_simeng_source>                           \
          -DCMAKE_BUILD_TYPE=Release                        \
          -DCMAKE_INSTALL_PREFIX=<target_install_directory>

Once configured, use `make` (or your preferred build tool) to build, and
use `make install` to install.

## Running tests

SimEng uses [googletest](https://github.com/google/googletest) for unit tests.
The sources are included as a git submodule, which need to be fetched in one of two ways:

1. If cloning for the first time, use the `--recurse-submodules` option:
```bash
git clone --recurse-submodules https://github.com/UoB-HPC/SimEng.git
```
2. If you already have a clone, update the submodules:
```bash
git submodule init
git submodule update
```

To run the tests, call the `test` executable from your build folder:

```bash
./test/test
```
