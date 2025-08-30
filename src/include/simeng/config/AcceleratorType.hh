#pragma once

#include "simeng/Instruction.hh"

namespace simeng {
namespace config {

/** The type of accelerator to model. */
enum class AcceleratorType : Instruction::accelerator_id_t {
  /** An undefined accelerator. Usually indicates invalid value in the config.
   */
  Undefined = 0,
  /** SME accelerator for AArch64
   * (see `simeng::models::accelerator::SmeAccelerator`). */
  AArch64_SME,
};

/** Parses the string to an AcceleratorType. */
AcceleratorType parseAcceleratorType(const std::string& str) noexcept;

/** Produces a full AcceleratorType name string based on values from a config.
 */
std::string acceleratorTypeNameFromConfig(const std::string& isa,
                                          const std::string& type);

/** Returns a printable representation of the provided AcceleratorType. */
constexpr const char* acceleratorTypeString(
    const AcceleratorType type) noexcept {
#define name_case(TYPE)       \
  case AcceleratorType::TYPE: \
    return #TYPE;

  // clang-format off
  switch (type) {
    name_case(AArch64_SME)

    case AcceleratorType::Undefined:
    default:
      return "Undefined";
  }
  // clang-format on
}

/** Returns a unique accelerator ID based on the type. If type is `Undefined`,
 * `Instruction::NO_ACCELERATOR` is returned. */
Instruction::accelerator_id_t acceleratorIdFromType(AcceleratorType type);

}  // namespace config
}  // namespace simeng
