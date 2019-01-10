#include "registerFile.hh"

#include <iostream>

namespace simeng {

std::ostream &operator<<(std::ostream &os, Register const &reg) {
  return os << reg.tag;
}

bool Register::operator==(Register other) {
  return (other.type == type && other.tag == tag);
}

RegisterFile::RegisterFile(std::vector<uint16_t> registerFileSizes) {
  registerFiles =
      std::vector<std::vector<RegisterValue>>(registerFileSizes.size());

  for (auto type = 0; type < registerFileSizes.size(); type++) {
    auto registerCount = registerFileSizes[type];
    registerFiles[type] =
        std::vector<RegisterValue>(registerCount, RegisterValue(0, 8));
    // for (auto i = 0; i < registerCount; i++) {
    //     auto a = RegisterValue(0, 8);
    //     registerFiles[type][i] = a;
    // }
  }
}

RegisterValue RegisterFile::get(Register reg) {
  return registerFiles[reg.type][reg.tag];
}

void RegisterFile::set(Register reg, const RegisterValue &value) {
  registerFiles[reg.type][reg.tag] = value;
}

}  // namespace simeng
