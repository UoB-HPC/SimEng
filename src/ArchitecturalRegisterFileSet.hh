#pragma once

#include "RegisterFileSet.hh"

namespace simeng {

class ArchitecturalRegisterFileSet {
 public:
  ArchitecturalRegisterFileSet(RegisterFileSet& physicalRegisterFileSet);

  /** Read the value of the specified register. */
  virtual RegisterValue get(Register reg) const;

  /** Set a register as the specified value. */
  virtual void set(Register reg, const RegisterValue& value);

 private:
  RegisterFileSet& physicalRegisterFileSet_;
};

}  // namespace simeng
