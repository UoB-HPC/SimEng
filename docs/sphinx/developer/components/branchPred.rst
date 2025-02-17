Branch prediction
=================

SimEng's fetch unit is supplied with an instance of the abstract ``BranchPredictor`` class to enable speculative execution. 

Access to the ``BranchPredictor`` is supported through the ``predict``, ``update``, and ``flush`` functions. ``predict`` provides a branch prediction, both target and direction, for a branch instruction. ``update`` updates the branch predictor's prediction mechanism on the actual outcome of a branch. ``flush`` provides algorithm specific flushing functionality.

The ``predict`` function is passed an instruction address, branch type, and a possible known target. The branch type argument currently supports the following types:

- ``Conditional``
- ``LoopClosing``
- ``Return``
- ``SubroutineCall``
- ``Unconditional``

The usage of these parameters within a branch predictor's ``predict`` function is algorithm specific.

The ``update`` function is passed the branch outcome, the instruction address, and the branch type. From this information, any algorithms or branch structures may be updated.

The state of the branch predictor when ``predict`` is called on a branch is stored in the ``ftq`` to be used by the ``update`` function.  For instance, the perceptron predictor stores the globalHistory and confidence for each prediction, but future predictors may store alternative state. The ``ftq`` is a queue that has an entry for each in-flight branch.  A single entry is added to the back of the ftq on ``predict``, and a single entry is removed from the front of the queue on ``update`` and from the back of the queue on ``flush``.

Generic Predictor
-----------------

The algorithm(s) held within a ``BranchPredictor`` class instance can be model-specific, however, SimEng provides a ``GenericPredictor`` which contains the following logic.

Global History
    For indexing relevant prediction structures, a global history can be utilised. The global history value stores the n most recent branch direction outcomes in an unsigned integer, with the least-significant bit being the most recent branch direction. The global history is speculatively updated on ``predict``, and is corrected if needed on ``update`` and ``flush``.  To facilitate this speculative updating, and rolling-back on correction, for a global history of n the branch predictor keeps track of the 2n most recent branch outcomes.  Valid values for Global History are 1-32.

Branch Target Buffer (BTB)
    For each entry, the BTB stores the most recent target along with an n-bit saturating counter for an associated direction. The indexing of this structure uses the lower bits of an instruction address XOR'ed with the current global branch history value.

    If the supplied branch type is ``Unconditional``, then the predicted direction is overridden to be taken. If the supplied branch type is ``Conditional`` and the predicted direction is not taken, then the predicted target is overridden to be the next sequential instruction.

Return Address Stack (RAS)
    Identified through the supplied branch type, Return instructions pop values off of the RAS to get their branch target whilst Branch-and-Link instructions push values onto the RAS, for later use by the Branch-and-Link instruction's corresponding Return instruction.

Static Prediction
    Based on the chosen static prediction method of "always taken" or "always not taken", the n-bit saturating counter value in the initial entries of the BTB structure are filled with the weakest variant of taken or not-taken respectively.

Perceptron Predictor
--------------------
The ``PerceptronPredictor`` has the same overall structure as the ``GenericPredictor`` but replaces the saturating counter as a means for direction prediction with a perceptron.  The ``PerceptronPredictor`` contains the following logic.

Global History
    For indexing relevant prediction structures, a global history can be utilised. The global history value stores the n most recent branch direction outcomes in an unsigned integer, with the least-significant bit being the most recent branch direction. The global history is speculatively updated on ``predict``, and is corrected if needed on ``update`` and ``flush``.  To facilitate this speculative updating, and rolling-back on correction, for a global history of n the branch predictor keeps track of the 2n most recent branch outcomes.  Valid values for Global History are 1-32.

Branch Target Buffer (BTB)
    For each entry, the BTB stores the most recent target along with a perceptron for an associated direction. The indexing of this structure uses the lower, non-zero bits of an instruction address XOR'ed with the current global branch history value.

    The direction prediction is obtained from the perceptron by taking its dot-product with the global history.  The prediction is not taken if this is negative, or taken otherwise.  The perceptron is updated when its prediction is wrong or when the magnitude of the dot-product is below a pre-determined threshold (i.e., the confidence of the prediction is low).  To update, each ith weight of the perceptron is incremented if the actual outcome of the branch is the same as the ith bit of ``globalHistory_``, and decremented otherwise.

    If the supplied branch type is ``Unconditional``, then the predicted direction is overridden to be taken. If the supplied branch type is ``Conditional`` and the predicted direction is not taken, then the predicted target is overridden to be the next sequential instruction.

Return Address Stack (RAS)
    Identified through the supplied branch type, Return instructions pop values off of the RAS to get their branch target whilst Branch-and-Link instructions push values onto the RAS, for later use by the Branch-and-Link instruction's corresponding Return instruction.