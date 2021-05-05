Docker
======

You can find Docker containers of SimEng `on DockerHub
<https://hub.docker.com/r/uobhpc/simeng>`_.
To get an interactive session in a container with SimEng installed, run:

.. code-block:: text

    docker run -it uobhpc/simeng

The `simeng` binary is on the default path.

A development version is also available, which contains the SimEng source code and all the build dependencies installed:

.. code-block:: text

    docker run -it uobhpc/simeng:dev

In the development container, the source code can be found in `/root/SimEng`.

If you don't want to use the pre-built container images, you can build your own:

.. code-block:: text

    docker build -t uobhpc/simeng .                   # For the release container
    docker build --target dev -t uobhpc/simeng:dev .  # For the development container
