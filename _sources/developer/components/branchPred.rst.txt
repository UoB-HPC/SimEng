Branch prediction
=================

SimEng's fetch unit is supplied with an instance of the abstract ``BranchPredictor`` class to enable speculative execution. 

Access to the ``BranchPredictor`` is supported through the ``predict`` and ``update`` functions with the former providing a branch prediction, both target and direction, and the latter updating an instructions' prediction. The ``predict`` function is passed an instruction object allowing for branch algorithms to utilise instruction information such as address and architecture-specific instruction classifiers. The ``update`` function is passed the branch outcome, along with the instruction object itself, so that any algorithms or branch structures may be updated.

The algorithm(s) held within a ``BranchPredictor`` class instance can be model-specific, however, SimEng provides a set of predictors detailed below.

AlwaysNotTakenPredictor
-----------------------

The ``AlwaysNotTakenPredictor`` is the simplest available branch predictor. It is a static predictor, only providing a "not taken" branch direction with no branch target prediction and no update functionality.


BTBPredictor
------------

A more complex branch predictor is the ``BTBPredictor`` utilising a Branch Target Buffer (BTB) and a branch direction buffer. Both structures are indexed by the instruction address, after the application of a mask, and store previous outcomes of executed branches.

Access to a structure entry with no previous history will supply a "not taken" direction prediction with no known target, similar to the ``AlwaysNotTakenPredictor``.

BTB_BWTPredictor
----------------

Based on the algorithms used by the A64FX processor, the ``BTB_BWTPredictor`` branch predictor utilises a 4-way associative BTB-style structure with each entry storing a 2-bit direction agreement policy and branch target. An agreement policy assigns an agreement bias value against a chosen branch direction such that, ``11`` relates to a strong agreement and ``00`` a strong disagreement.

To index this structure, the instructions' address is used in conjunction with a set of branch directions histories via an XOR operation. This indexing policy aims to reduce the contention of structure entries between branch instructions.

To accompany the BTB-style structure, a return address stack (RAS) is also used. The RAS allows for branch and link instructions to push a return address onto a stack, and return instructions to pop an address from the stack. This methodology allows for a strong prediction of the branch target for return instructions.