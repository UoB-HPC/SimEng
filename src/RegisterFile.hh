#pragma once

#include "RegisterValue.hh"

#include <vector>

namespace simeng {

/** A generic register identifier. */
struct Register {
  /** An identifier representing the type of register - e.g. 0 = general, 1 =
   * vector. Used to determine which register set to access. */
  uint8_t type;

  /** A tag identifying the register. May correspond to either physical or
   * architectural register, depending on point of usage. */
  uint16_t tag;

  /** Check for equality of two register identifiers. */
  bool operator==(Register other) const;
};
std::ostream& operator<<(std::ostream& os, simeng::Register const& reg);

/** Defines a set of registers in the register file. */
struct RegisterFileStructure {
  /** The number of bytes per register. */
  uint8_t bytes;
  /** The number of registers. */
  uint16_t quantity;
};

/** A processor register file set. Holds the physical registers for each
 * register type. */
class RegisterFile {
 public:
  /** Initialise multiple register groups. Each entry in `registerFileSizes`
   * states the number of registers that should be available for the register
   * type corresponding to the entry's index. */
  RegisterFile(std::vector<uint16_t> registerFileSizes);

  /** Read the value of the specified register. */
  RegisterValue get(Register reg) const;

  /** Set a register as the specified value. */
  void set(Register reg, const RegisterValue& value);

 private:
  /** The set of register files. Each entry in the outer vector corresponds to a
   * register type, according to its index. */
  std::vector<std::vector<RegisterValue>> registerFiles;
};

}  // namespace simeng
