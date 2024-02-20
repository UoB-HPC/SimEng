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
  /** Make enough space for an SME operand in container - stop using fixed size
   * array and instead use vector. */
  constexpr void addSMEOperand(const uint16_t numSMERows) {
    if (std::holds_alternative<std::array<T, arrSize>>(var_)) {
      // Get values in array
      auto arr = std::get<std::array<T, arrSize>>(var_);
      // Place into vector
      var_ = std::vector<T>{arr.begin(), arr.end()};
      // Re-size vector to accomodate SME instruction - make sure to keep all
      // current operands and make space for any additional operands that can be
      // present with SME instructions
      std::get<std::vector<T>>(var_).resize(
          arr.size() + ADDITIONAL_SME_REGISTERS + numSMERows);
    } else {
      // std::vector already in use; only need to allocate enough room for
      // additional SME operand.
      this->resize(this->size() + numSMERows);
    }
  }

  /** Resize the vector to be the same size as `numRegs`. Primarily used to
   * ensure any unused vector indexes introduced in addSMEOperand() are removed.
   */
  constexpr void resize(uint16_t numRegs) {
    assert(std::holds_alternative<std::vector<T>>(var_) &&
           "resize can only be called when the active member is std::vector "
           "(i.e. after a call to addSMEOperand() has been made)");
    std::get<std::vector<T>>(var_).resize(numRegs);
  }

  /** Get the size of the currently active data structure. */
  [[nodiscard]] constexpr size_t size() const {
    return std::visit([](auto&& arg) -> size_t { return arg.size(); }, var_);
  }

  /** Implementation of the [] operator to apply to the currently active variant
   * member. */
  [[nodiscard]] constexpr const T& operator[](size_t idx) const {
    return std::visit([=](auto&& arg) -> const T& { return (arg[idx]); }, var_);
  }

  /** Implementation of the [] operator to apply to the currently active variant
   * member. */
  [[nodiscard]] constexpr T& operator[](size_t idx) {
    return std::visit([=](auto&& arg) -> T& { return (arg[idx]); }, var_);
  }

  /** Retrieve the underlying pointer of the active variant member. */
  [[nodiscard]] constexpr const T* data() const noexcept {
    return std::visit([](auto&& arg) -> const T* { return arg.data(); }, var_);
  }

  /** Retrieve the underlying pointer of the active variant member. */
  [[nodiscard]] constexpr T* data() noexcept {
    return std::visit([](auto&& arg) -> T* { return arg.data(); }, var_);
  }

 private:
  /** Variant containing a fixed size array (used by default) and a vector, the
   * latter of which can be utilised by calling addSMEOperand(). */
  std::variant<std::array<T, arrSize>, std::vector<T>> var_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng