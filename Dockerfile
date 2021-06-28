# Builder container
FROM ubuntu:20.04 AS dev

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      build-essential \
      cmake \
      git \
      llvm-9-dev \
      ninja-build \
      zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY . /root/SimEng

RUN cd /root/SimEng && \
    rm -rf build && \
    CC=gcc CXX=g++ cmake -Bbuild -S. -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DSIMENG_USE_EXTERNAL_LLVM=ON -DLLVM_DIR=/usr/lib/llvm-9/cmake && \
    cd build && \
    ninja && \
    ninja install

# Tar file to preserve links when copying to the release container
RUN cd /usr/local && \
    tar -cf simeng.tar.gz bin/simeng lib/libsimeng* include/simeng/*


## Release container
FROM ubuntu:20.04

COPY --from=dev /usr/local/simeng.tar.gz /root/

WORKDIR /root

RUN cd /usr/local && tar xf /root/simeng.tar.gz
