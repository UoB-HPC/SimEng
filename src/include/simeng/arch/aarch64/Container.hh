#pragma once

#include <array>
#include <cstdint>
#include <variant>
#include <vector>

namespace simeng {
namespace arch {
namespace aarch64 {

/** The maximum number of source registers a non-SME instruction can have. */
const uint8_t MAX_SOURCE_REGISTERS = 6;

/** The maximum number of destination registers a non-SME instruction can have.
 */
const uint8_t MAX_DESTINATION_REGISTERS = 5;

/** The maximum number of source/destination operands an SME instruction can
 * have in addition to any ZA operands. */
const uint8_t ADDITIONAL_SME_REGISTERS = 8;

/** Simple class to allow AArch64 instructions to use std::array for operands in
 * most cases, but for SME instructions a std::vector can be utilised to allow
 * for the increased number of operands used. */
template <typename T, const uint8_t arrSize>
class operandContainer {
 public:
  /** Tells container it is handling SME operands - stop using a fixed size
   * array and insead use a vector. */
  constexpr void makeSME(const uint16_t numSMERows) {
    // Ensure that std::array is currently in use
    if (std::holds_alternative<std::array<T, arrSize>>(var_)) {
      // Get values in array
      auto arr = std::get<std::array<T, arrSize>>(var_);
      // Place into vector
      var_ = std::vector<T>{arr.begin(), arr.end()};
      // Re-size vector to accomodate SME instruction
      std::get<std::vector<T>>(var_).resize(
          arr.size() + ADDITIONAL_SME_REGISTERS + numSMERows);
    }
    // Otherwise, makeSME already called - do nothing
  }

  /** Resize the vector to be the same size as `numRegs` if makeSME() has been
   * called. */
  constexpr void resize(uint16_t numRegs) {
    if (std::holds_alternative<std::vector<T>>(var_)) {
      std::get<std::vector<T>>(var_).resize(numRegs);
    }
  }

  [[nodiscard]] constexpr const T& operator[](size_t idx) const {
    return std::visit([=](auto&& arg) -> const T& { return (arg[idx]); }, var_);
  }

  [[nodiscard]] constexpr T& operator[](size_t idx) {
    return std::visit([=](auto&& arg) -> T& { return (arg[idx]); }, var_);
  }

  [[nodiscard]] constexpr const T* data() const noexcept {
    return std::visit([](auto&& arg) -> const T* { return arg.data(); }, var_);
  }

  [[nodiscard]] constexpr T* data() noexcept {
    return std::visit([](auto&& arg) -> T* { return arg.data(); }, var_);
  }

 private:
  /** Variant holding the source objects. */
  std::variant<std::array<T, arrSize>, std::vector<T>> var_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng