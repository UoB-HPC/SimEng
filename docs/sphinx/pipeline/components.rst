Common Components
=================

The SimEng library contains numerous components for use within the default models, as well as for facilitating the creation of custom models.

.. contents:: Contents

RegisterFileSet
---------------

The ``RegisterFileSet`` class models a set of register files, each containing any number of equally-sized registers. The default models each contain a single ``RegisterFileSet`` instance, with each register file within the set representing all registers of a discrete type (i.e., general purpose, floating point, etc.).

All data within the register files are stored as ``RegisterValue`` instances, and may be retrieved or modified using a ``Register`` identifier (see Registers for more information).
