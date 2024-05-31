#pragma once

#include <vector>
#include <iostream>

#include "simeng/Register.hh"
#include "simeng/RegisterValue.hh"

namespace simeng {

/** Defines the structure of a register file. */
struct RegisterFileStructure {
  /** The number of bytes per register. */
  uint16_t bytes;
  /** The number of registers. */
  uint16_t quantity;
  /** Check for the equality of two RegisterFileStructure structs. */
  bool operator==(const RegisterFileStructure& other) const {
    return (bytes == other.bytes) && (quantity == other.quantity);
  }
};

/** A processor register file set. Holds the physical registers for each
 * register file. */
class RegisterFileSet {
 public:
  /** Constructs a set of register files, defined by `registerFileStructures`.
   */
  RegisterFileSet(std::vector<RegisterFileStructure> registerFileStructures);

  /** Read the value of the specified register. */
  const RegisterValue& get(Register reg) const;

  /** Set a register as the specified value. */
  void set(Register reg, const RegisterValue& value);

 private:
  /** The set of register files. Each entry in the outer vector corresponds to a
   * register file, and the inner vectors are the registers. */
  std::vector<std::vector<RegisterValue>> registerFiles;
};

}  // namespace simeng
