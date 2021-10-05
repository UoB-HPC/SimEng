The Simulation Engine - SimEng
==============================

.. toctree::
   :maxdepth: 2
   :caption: Developer Documentation
   :hidden:

   developer/index
   developer/developerInfo
   developer/concepts/index
   developer/components/index
   developer/models/index
   developer/arch/index
   developer/test/index

.. toctree::
   :maxdepth: 2
   :caption: User Documentation
   :hidden:

   user/index
   user/building_simeng
   user/running_simeng
   user/configuring_simeng
   user/creating_binaries
   user/docker

SimEng is a framework for building modern, cycle-accurate processor simulators. Its goals are to be:

- Fast, typically 4-5X faster than gem5
- Easy to use and modify to model desired microarchitecture configurations. New cores can be configured in just a few hours
- Scalable, from simple scalar microarchitectures up to the most sophisticated, superscalar, out-of-order designs
- Capable of supporting a wide range of instruction set architectures (ISAs), starting with Armv8 but eventually including RISC-V, x86, POWER, etc.
- Accurate, aiming for simulated cycle times being within 5-10% of real hardware
- Open source, with a permissive license to enable collaboration across academia and industry

SimEng places an emphasis on performance and ease of use, whilst maintaining a clean, modern, simple and well-documented code base. For example, the current out-of-order (OoO) model is implemented in around 10,000 lines of simple C++, with another 9,000 lines or so implementing the specifics of the Armv8 ISA, and around 13,000 lines of code in the accompanying test suite. SimEng should be simple to read and understand, making it ideal to modify to your requirements and include it in your projects.


Features
--------

Currently, SimEng targets the Armv8+SVE ISA with the ability to model up to out-of-order, superscalar, single-core processors, and to emulate a subset of Linux system-calls. It supports statically compiled C and Fortran binaries that run on real hardware. SimEng currently models memory as an infinite L1 cache, i.e. it assumes that all loads and stores hit the L1 cache; a future release will add a proper memory hierarchy model (see the discussion about SST below).

The main component provided by the simulator is a discrete processor core model, shown in diagrammatic form below.  This model accepts a clock signal and supports a memory access interface. A single YAML format configuration file can be passed to the simulation to specify models of existing microarchitectures, such as Marvell's ThunderX2 or Fujitsu's A64fx, or to model hypothetical core designs.

.. image:: assets/simeng_generic_core_model.png
  :width: 500
  :alt: Generic Core Model

A future release of SimEng will support multi-core and memory hierarchy simulation by integrating with the `Structural Simulation Toolkit <http://sst-simulator.org/>`_ (SST). We have already implemented a prototype integrating SimEng with SST to provide a model of the memory hierarchy, and this worked well.


Talks and presentations
-----------------------

SimEng was first presented by `Professor Simon McIntosh-Smith <http://uob-hpc.github.io/SimonMS/>`_ at the 2019 Workshop on Modeling & Simulation of Systems and Applications (ModSim):

- ModSim 2019 - :download:`Enabling Processor Design Space Exploration with SimEng <assets/simeng_modsim_2019.pdf>`

For the most recent presentation on SimEng's progress and status, see:

- :download:`Modelling Advanced Arm-based CPUs with SimEng <assets/simeng_arm_cpus.pdf>`


Release
-------

This is SimEng's second release, so should be considered beta level software (version 0.9.0). We expect you to find issues, primarily in unimplemented instructions or unimplemented system calls. Please let us know when you hit these, either by submitting a pull request (PR), or by filing an issue on the Github repo. You can find the all the code and associated test suites for SimEng in the `GitHub repository <https://github.com/UoB-HPC/SimEng>`_. The file `RELEASE_NOTES.txt <https://github.com/UoB-HPC/SimEng/blob/main/RELEASE-NOTES.txt>`_, found in the root of the project, explains the status of the project and includes other relevant information from the SimEng development team.

SimEng is released under the same license as LLVM, the permissive `Apache 2.0 <https://www.apache.org/licenses/LICENSE-2.0>`_ license. We are passionate about enabling experimentation with computer architectures, and want users and developers in academic and industry to have complete freedom to use SimEng anyway they wish, including using it in commercial settings.


External project usage
----------------------

While we have tried to minimise SimEng's dependencies to keep it as simple as possible, it does make use of a small number of libraries and frameworks to provide crucial capabilities:

- `Capstone disassembly engine <https://www.capstone-engine.org/>`_ - Provides instruction decoding for Armv8, RISC-V, x86 and other important ISAs
- `Yaml-cpp <https://github.com/jbeder/yaml-cpp>`_ - Parsing YAML configuration files
- `GoogleTest <https://github.com/google/googletest>`_ - Framework for the test suites
- `LLVM <https://github.com/llvm-mirror/llvm>`_ - Generation of binaries for use in the regression test suite


Contributors
------------

Major contributors to SimEng to date include:

Project leader:

- Simon McIntosh-Smith
    
Original SimEng design and implementation:

- Hal Jones
- James Price

Current development team:

- Jack Jones (lead developer) 
- Harry Waugh

Code reviewers:

- Andrei Poenaru

Build structure design:

- Tom Lin

Internship contributions:

- Daniel Weaver
- Finn Wilkinson
- Mutalib Mohammed
- Seunghun Lee
- Ainsley Rutterford

Funding
-------

The SimEng development team is grateful for the funding which has made this project possible, which to date has been from the UKRI/EPSRC ASiMoV project (Advanced Simulation and Modelling of Virtual systems), number EP/S005072/1, and from Arm via the Arm Centre of Excellence in HPC at the University of Bristol.

