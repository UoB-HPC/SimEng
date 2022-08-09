#pragma once

#include "simeng/MemoryInterface.hh"

int runGDBStub(simeng::Core& core, simeng::MemoryInterface& dataMemory, simeng::MemoryInterface& instructionMemory);