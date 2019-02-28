#include "RegisterFileSet.hh"

#include <iostream>

namespace simeng {

std::ostream& operator<<(std::ostream& os, Register const& reg) {
  return os << reg.tag;
}

bool Register::operator==(Register other) const {
  return (other.type == type && other.tag == tag);
}

RegisterFileSet::RegisterFileSet(
    std::vector<RegisterFileStructure> registerFileStructures)
    : registerFiles(registerFileStructures.size()) {
  for (size_t type = 0; type < registerFileStructures.size(); type++) {
    const auto& structure = registerFileStructures[type];
    registerFiles[type] = std::vector<RegisterValue>(
        structure.quantity, RegisterValue(0, structure.bytes));
  }
}

RegisterValue RegisterFileSet::get(Register reg) const {
  return registerFiles[reg.type][reg.tag];
}

void RegisterFileSet::set(Register reg, const RegisterValue& value) {
  registerFiles[reg.type][reg.tag] = value;
}

}  // namespace simeng
