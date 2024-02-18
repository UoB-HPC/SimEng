#pragma once

#include <vector>

#include "simeng/Register.hh"
#include "simeng/RegisterValue.hh"
#include "simeng/memory/MemoryAccessTarget.hh"

namespace simeng {

namespace arch {

/** The types of changes that can be made to values within the process state. */
enum class ChangeType { REPLACEMENT, INCREMENT, DECREMENT };

/** A structure describing a set of changes to the process state. */
struct ProcessStateChange {
  /** Type of changes to be made */
  ChangeType type;
  /** Registers to modify */
  std::vector<Register> modifiedRegisters;
  /** Values to set modified registers to */
  std::vector<RegisterValue> modifiedRegisterValues;
  /** Memory address/width pairs to modify */
  std::vector<memory::MemoryAccessTarget> memoryAddresses;
  /** Values to write to memory */
  std::vector<RegisterValue> memoryAddressValues;
};

}  // namespace arch
}  // namespace simeng