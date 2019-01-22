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
