#pragma once

#include <vector>

#include "simeng/RegisterValue.hh"

namespace simeng {

/** A generic register identifier. */
struct Register {
  /** An identifier representing the type of register - e.g. 0 = general, 1 =
   * vector. Used to determine which register file to access. */
  uint8_t type;

  /** A tag identifying the register. May correspond to either physical or
   * architectural register, depending on point of usage. */
  uint16_t tag;

  /** Default Constructor. */
  Register(){};

  /** Constructor for `Register` with a given register file type and register
   * tag. */
  Register(uint8_t type, uint16_t tag) : type(type), tag(tag){};

  /** Check for equality of two register identifiers. */
  bool operator==(const Register& other) const;

  /** Check for inequality of two register identifiers. */
  bool operator!=(const Register& other) const;

  /** Default copy constructor for Register. */
  Register(const Register& res) = default;

  /** Default move constructor for Register to enable copy elision
   * whenever it is possible. */
  Register(Register&& res) = default;

  /** Default copy assignment operator for Register. */
  Register& operator=(const Register& res) = default;

  /** Default move assignment operator for Register to enable copy
   * elision whenever it is possible. */
  Register& operator=(Register&& res) = default;
};
std::ostream& operator<<(std::ostream& os, simeng::Register const& reg);

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
