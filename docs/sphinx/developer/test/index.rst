Testing
=======

SimEng's internal test suite has been created to ensure the correct functionality of its core components and simulation of instructions are maintained throughout development. The former case is supported through the unit test suite whilst the latter the regression test suite. 

SimEng uses the `GoogleTest <https://github.com/google/googletest>`_ framework to create both the regression and unit test suites. The regression suite also utilises the `LLVM Project <https://github.com/llvm-mirror/llvm>`_ to assemble hand-written assembly code into a source program as to then be run through the SimEng pipeline.

.. contents:: Contents

Regression suite
----------------

Test lifecycle
**************

The regression suite tests consist of a set of assembly instructions, an instance of a SimEng model, and an expectation of values in registers or memory. The creation of the SimEng model is performed by the ``RegressionTest`` class's ``run`` function in ``test/regression/RegressionTest.cc``. The ``RegressionTest`` class serves as an ISA agnostic mediator to a SimEng model instance during testing.

The ``run`` function takes a source and triple parameter, which supply the assembly instructions and target information (e.g. aarch64) respectively. Both are passed to the ``assemble`` function, which creates a flat binary containing the supplied instructions for the defined target. After the flat binary is loaded into the simulated process memory, the SimEng model is created in a similar fashion to that outside of the test environment in ``src/tools/simeng/main.cc``.

Once the simulation has been run, the SimEng model instance persists so that the test can inspect the value of architectural registers and memory for comparison against an expected value. Each test can be parameterised with one of three values from the set ``{EMULATION, INORDER, OUTOFORDER}`` to denote the :ref:`archetype <archetypes>` of the SimEng core to be used.

Prior to the test being run, a ``initialHeapData_`` vector can be manipulated from within a test. Later, this vector can be used to populate the SimEng model heap and accessed during simulation.

Current regression suites
*************************

Each ISA is expected to have its own folder within the regression test directory. Each folder should have an inherited instance of the ``RegressionTest`` class (for example ``AArch64RegressionTest.cc``) to supply ISA specific conversions between the test and the ``RegressionTest`` class's instance of the SimEng model.

AArch64 regression suite
''''''''''''''''''''''''

In addition to tests for the instruction functionality of the ISA, that are located in the ``test/regression/aarch64/instructions/`` folder, the aarch64 regression test suite also offers the following test cases:

- Exception: Test non-supervisor call based exceptions.
- LoadStoreQueue: Test the correct implementation of load and store instructions concerning their interaction with the LSQ.
- MicroOperation: Test the supported instruction splitting provides the correct output from the execution of said instructions.
- SmokeTest: Trivial ISA related tests.
- Syscall: Ensure the correct functionality of aarch64 system calls.
- SystemRegisters: Ensure aarch64 system registers are correctly written to and read from.

Each aarch64 test case structure consists of a set of GoogleTest parameterised test functions, ``TEST_P``, and a single ``INSTANTIATE_TEST_SUITE_P`` call to instantiate and run all ``TEST_P`` calls. The test case name is defined at the top of each ``*.cc`` test file (e.g. ``using SmokeTest = AArch64RegressionTest``) and the name of the test is defined as the second parameter in each ``TEST_P`` call.

Within the ``INSTANTIATE_TEST_SUITE_P`` call, multiple parameters (from the ``{EMULATION, INORDER, OUTOFORDER}`` set) can be selected, allowing for multiple instances of the same test to be run through different core archetypes.

The standard structure of an AArch64 regression test body is as followed:

.. code-block:: text

   TEST_P(Test_Case_Name, Test_Name) {
      ** Any additions to initialHeapData_ **
      
      RUN_AARCH64("R(
         ...
         instructions to be run
         ...
      )");

      ** Comparisons against values in the SimEng model after simulation **
   }

**Note**, the ``RUN_AARCH64`` function is a proxy call to the ``run`` function in the ``RegressionTest`` class with the "aarch64" target defined. Also, helper functions for comparrisons against the SimEng model are implemented and well documented in ``test/regression/aarch64/AArch64RegressionTest.hh``.

Unit suite
----------

The tests contained in SimEng's unit test suite create an isolated instance of a SimEng component. During the tests, hardcoded inputs are supplied to the component and specific functions belonging to the component are invoked. GoogleTest ``EXPECT`` functions are used throughout this process to form expectations. These expectations relate to the return values of functions and the logic held within them, for example, the calling of other functions with defined parameters.

Due to the use of isolated instances of SimEng components, certain linked objects or passed inputs have not interacted with the expected prior stages of the processor pipeline. Therefore, they are deemed to be in an incorrect state, for the test context, and may cause unrealistic behaviour. To combat this, the GoogleTest `gMock <https://github.com/google/googletest/tree/master/googlemock>`_ library has been used to create mock instances of these objects. When using these mock instances, function logic and return values can be pre-defined and thus mimic the correct behaviour for the test context. Currently, mock instances exist for the following abstract classes:

- Architecture 
- BranchPredictor
- Instruction
- MemoryInterface

Running the test suites
-----------------------

Whilst ``cmake --build {BUILD_DIR} --target test`` can be used to run both the unit and regression test suites sequentially, further refinement on what test are run can be achieved via GoogleTest functionality. GoogleTest provides a ``--gtest_filter="<regex>"`` filter command which can be passed as an argument to either test suite, the filter is passed via a regular expression (regex). Full test names typically take the form of:

Parameterised test: 
   ``<INSTANTIATE_TEST_SUITE_P name>/<test case name>.<test name>/<parameter value>``
Non-parameterised test: 
   ``<test case name>.<test name>``

An example of its use to filter the aarch64 regression test suite:

.. code-block:: text

   ./test/regression/aarch64/regression-aarch64 --gtest_filter="*InstNeon*"

This applied filter would only run those tests in the aarch64 regression test suite with the *InstNeon* string in their full test name.
