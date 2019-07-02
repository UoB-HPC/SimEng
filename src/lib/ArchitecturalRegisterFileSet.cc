#include "ArchitecturalRegisterFileSet.hh"

namespace simeng {

ArchitecturalRegisterFileSet::ArchitecturalRegisterFileSet(
    RegisterFileSet& physicalRegisterFileSet)
    : physicalRegisterFileSet_(physicalRegisterFileSet) {}

RegisterValue ArchitecturalRegisterFileSet::get(Register reg) const {
  return physicalRegisterFileSet_.get(reg);
}

void ArchitecturalRegisterFileSet::set(Register reg,
                                       const RegisterValue& value) {
  return physicalRegisterFileSet_.set(reg, value);
}

}  // namespace simeng
