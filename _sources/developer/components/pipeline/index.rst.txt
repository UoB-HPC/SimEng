Pipeline
========

The SimEng pipeline consists of a set of standard self-contained "units", which represent the logic for the various stages of a processor pipeline. These units are designed to be generic representations of the typical functionality found in their hardware counterparts to encourage reusability between models. 

Beyond these pipeline units, appropriate instructions may flow to other objects termed "common components". These components provide additional logic that may not have such typical functionality, as the pipeline units do, and thus may required alterations to better suit the model. These components include:

``ReorderBuffer``: Holds an ordered list of ‘in-flight’ instructions, with facilities for committing instructions and rewinding register allocations.

``LoadStoreQueue``: Holds ordered queues of load/store instructions, with facilities for servicing memory accesses and checking for address clashes.


.. toctree::
   :maxdepth: 2

   units
   components