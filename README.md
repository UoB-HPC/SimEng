# SimEng

The Simulation Engine framework (SimEng) provides a modern cycle-accurate processor simulator, with aims to be:

- Fast
- Easy to use and modify to desired configurations
- Scalable, supporting simulation of simple scalar cores, up to superscalar out-of-order designs
- Capable of supporting a wide range of ISAs, starting with ARMv8 but eventually including x86, RISC-V, POWER, etc.
- Open source, with a permissive license to enable collaboration across academia and industry

SimEng places an emphasis on performance and scalability, whilst maintaining a clean, modern, and well-documented code base.

## Getting started with SimEng

To get started with SimEng, please follow the instructions set out in our [User Documentation](https://uob-hpc.github.io/SimEng-Docs/users/index.html). This will cover how to download, build and run SimEng along with a brief overview on how it works.

If you are interested in developing further SimEng features, and are already familiar with the User Documentation please refer to our [Developer Documentation](https://uob-hpc.github.io/SimEng-Docs/developers.html). This offers further depth on how SimEng works and the reasoning behind design choices.

        git pull origin master
        git submodule update --init

Configure with CMake, specifying the path to your desired installation directory if necessary:

    cmake <path_to_simeng_repository>                       \
          -DCMAKE_BUILD_TYPE=Release                        \
          -DCMAKE_INSTALL_PREFIX=<target_install_directory>

Once configured, use `make` (or your preferred build tool) to build.

Run `make test` to run the SimEng regression tests and unit tests.
Please report any test failures as [a GitHub issue](https://github.com/UoB-HPC/SimEng/issues).

Finally, run `make install` to install SimEng to the directory specified to CMake.

## Docker

You can find Docker containers of SimEng [on DockerHub](https://hub.docker.com/r/uobhpc/simeng).
To get an interactive session in a container with SimEng installed, run:

    docker run -it uobhpc/simeng

The `simeng` binary is on the default path.

A development version is also available at, which contains the SimEng source code and all the build dependencies installed:

    docker run -it uobhpc/simeng:dev

In the development container, the source code can be found in `/root/SimEng`.

If you don't want to use the pre-built container images, you can build your own:

    docker build -t uobhpc/simeng .                   # For the release container
    docker build --target dev -t uobhpc/simeng:dev .  # For the development container
