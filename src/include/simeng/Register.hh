#pragma once
#include <cstdint>
#include <iostream>

namespace simeng {

/** A generic register identifier. */
struct Register {
  /** An identifier representing the type of register - e.g. 0 = general, 1 =
   * vector. Used to determine which register file to access. */
  uint8_t type;

  /** A tag identifying the register. May correspond to either physical or
   * architectural register, depending on point of usage. */
  uint16_t tag;

  /** A boolean identifier for whether the creation of this register has been a
   * result of a register renaming scheme. */
  bool renamed = false;

  /** Check for equality of two register identifiers. */
  bool operator==(const Register& other) const {
    return (other.type == type && other.tag == tag);
  }

  /** Check for inequality of two register identifiers. */
  bool operator!=(const Register& other) const { return !(other == *this); }
};

}  // namespace simeng
