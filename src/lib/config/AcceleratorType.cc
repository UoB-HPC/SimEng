#include "simeng/config/AcceleratorType.hh"

namespace simeng {
namespace config {

AcceleratorType parseAcceleratorType(const std::string& str) noexcept {
#define return_if_matches(STR, TYPE) \
  if (STR == acceleratorTypeString(TYPE)) return TYPE;

  return_if_matches(str, AcceleratorType::AArch64_SME);
  return AcceleratorType::Undefined;
}

std::string acceleratorTypeNameFromConfig(const std::string& isa,
                                          const std::string& type) {
  auto fullType = isa;
  fullType += '_';
  fullType += type;
  return fullType;
}

Instruction::accelerator_id_t acceleratorIdFromType(AcceleratorType type) {
  if (type == AcceleratorType::Undefined) return Instruction::NO_ACCELERATOR;

  return static_cast<Instruction::accelerator_id_t>(type);
}

}  // namespace config
}  // namespace simeng
