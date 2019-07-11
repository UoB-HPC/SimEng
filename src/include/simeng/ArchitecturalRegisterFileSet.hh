#pragma once

#include "simeng/RegisterFileSet.hh"

namespace simeng {

/** An extendable architectural register file set class, for mapping
 * architectural registers to an underlying physical register file. This default
 * implementation provides a 1:1 mapping to a RegisterFileSet instance. */
class ArchitecturalRegisterFileSet {
 public:
  /** Create an architectural register file set that maps 1:1 to the supplied
   * physical register file. */
  ArchitecturalRegisterFileSet(RegisterFileSet& physicalRegisterFileSet);

  /** Read the value of the specified architectural register. */
  virtual RegisterValue get(Register reg) const;

  /** Set an architectural register as the specified value. */
  virtual void set(Register reg, const RegisterValue& value);

 private:
  /** The physical register file set to map onto. */
  RegisterFileSet& physicalRegisterFileSet_;
};

}  // namespace simeng
