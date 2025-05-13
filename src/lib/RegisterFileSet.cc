#include "simeng/RegisterFileSet.hh"

#include <iostream>

namespace simeng {

RegisterFileSet::RegisterFileSet(
    std::vector<RegisterFileStructure> registerFileStructures)
    : registerFiles(registerFileStructures.size()) {
  for (size_t type = 0; type < registerFileStructures.size(); type++) {
    const auto& structure = registerFileStructures[type];
    registerFiles[type] = std::vector<RegisterValue>(
        structure.quantity, RegisterValue(0, structure.bytes));
  }
}

const RegisterValue& RegisterFileSet::get(Register reg) const {
  return registerFiles[reg.type][reg.tag];
}

void RegisterFileSet::set(Register reg, const RegisterValue& value) {
  assert(value.size() != 0 &&
         "Attempted to write an zero sized value to a register");
  assert(value.size() == registerFiles[reg.type][reg.tag].size() &&
         "Attempted to write an incorrectly sized value to a register");
  registerFiles[reg.type][reg.tag] = value;
}

}  // namespace simeng
