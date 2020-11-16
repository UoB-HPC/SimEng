#!/bin/bash




build_and_run () {
   cd $SIMENG_TOP
   rm -rf build/* install/*

   cd $SIMENG_BUILD
   cmake $SIMENG_TOP -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$SIMENG_INSTALL
   make -j
   make install
   make test
}
