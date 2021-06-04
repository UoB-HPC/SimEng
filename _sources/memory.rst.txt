Memory
======

The SimEng core models simulate everything in a core up to and including the load/store units, but stop short of the memory system. This is to allow integration and interoperability with a wide range of external memory models, and to focus the development of SimEng primarily on the simulation of the core itself.

MemoryInterface
---------------

All SimEng components that interact with the memory system make memory access requests using supplied instances of the abstract ``MemoryInterface`` class.

``MemoryInterface`` access requests are asynchronous, and may be either reads or writes. All requests must supply a ``MemoryAccessTarget``, containing both the memory address and the number of bytes to access. While write requests receive no response, a read request may be responded to an indeterminate number of cycles later. The ``MemoryInterface::getCompletedReads`` function may be used to retrieve a list of the read requests that completed during the previous cycle. Once processed, responses should be dismissed using the ``MemoryInterface::clearCompletedReads`` function.

.. Note:: Future versions may update the interface to remove the need for the component to manually clear completed reads.

It is expected that all implementations of ``MemoryInterface`` should respect the order that requests are made: a read request following a write request to the same address should respond with the newly written value, rather than returning the old, stale result.

FlatMemoryInterface
*******************

For simpler models, a ``FlatMemoryInterface`` implementation is supplied. This is a simple wrapper around a byte array representing the process memory, and will always respond to all requests instantly and synchronously.
