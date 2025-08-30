#pragma once

#include <array>
#include <cstdint>
#include <variant>
#include <vector>

#include "simeng/Register.hh"
#include "simeng/RegisterValue.hh"
#include "simeng/serialization.hh"
#include "simeng/span.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** The maximum number of source registers a non-SME instruction can have. */
constexpr uint8_t MAX_SOURCE_REGISTERS = 7;

/** The maximum number of destination registers a non-SME instruction can have.
 */
constexpr uint8_t MAX_DESTINATION_REGISTERS = 5;

/** The maximum number of source/destination operands an SME instruction can
 * have in addition to any ZA operands. */
constexpr uint8_t ADDITIONAL_SME_REGISTERS = 11;

/** Simple class to allow AArch64 instructions to use std::array for operands in
 * most cases, but for SME instructions a std::vector can be utilised to allow
 * for the increased number of operands used. */
template <typename T, const uint8_t arrSize>
class operandContainer {
 public:
  typedef T value_type;
  typedef size_t size_type;
  typedef T* iterator;
  typedef const T* const_iterator;

  operandContainer() = default;

  /** Deserializes the container from the provided span of bytes. */
  explicit operandContainer(span<uint8_t>& serialized) {
    std::vector<T> var;

    size_type len = 0;
    deserialize_field(serialized, len);

    if constexpr (std::is_same_v<T, Register>) {
      const auto* data_ptr =
          reinterpret_cast<const value_type*>(serialized.data());
      const span data_span = {const_cast<value_type*>(data_ptr), len};
      var.insert(var.cend(), data_span.cbegin(), data_span.cend());

      const auto size = len * sizeof(value_type);
      serialized = {serialized.data() + size, serialized.size() - size};
    } else if constexpr (std::is_same_v<T, RegisterValue>) {
      var.reserve(len);
      for (size_type i = 0; i < len; i++) {
        using len_t =
            std::invoke_result_t<decltype(&RegisterValue::size), RegisterValue>;

        len_t val_len = 0;
        deserialize_field(serialized, val_len);
        assert(val_len <= static_cast<len_t>(static_cast<uint16_t>(-1)) &&
               "RegisterValue length overflow");

        const auto* data_ptr = reinterpret_cast<const char*>(serialized.data());
        var.emplace_back(data_ptr, static_cast<uint16_t>(val_len));

        serialized = {serialized.data() + val_len, serialized.size() - val_len};
      }
    } else {
      assert(false &&
             "Only containers of `Register` or `RegisterValue` can be "
             "deserialized");
    }

    var_ = std::move(var);
  }

  /** Make enough space for an SME operand in container - stop using fixed size
   * array and instead use vector. */
  constexpr void addSMEOperand(const uint16_t numSMERows) {
    if (std::holds_alternative<std::array<T, arrSize>>(var_)) {
      // Get values in array
      auto arr = std::get<std::array<T, arrSize>>(var_);
      // Place into vector
      var_ = std::vector<T>{arr.begin(), arr.end()};
      // Re-size vector to accommodate SME instruction - make sure to keep all
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
    return std::visit([=](auto&& arg) -> const T& { return arg[idx]; }, var_);
  }

  /** Implementation of the [] operator to apply to the currently active variant
   * member. */
  [[nodiscard]] constexpr T& operator[](size_t idx) {
    return std::visit([=](auto&& arg) -> T& { return arg[idx]; }, var_);
  }

  /** Retrieve the underlying pointer of the active variant member. */
  [[nodiscard]] constexpr const T* data() const noexcept {
    return std::visit([](auto&& arg) -> const T* { return arg.data(); }, var_);
  }

  /** Retrieve the underlying pointer of the active variant member. */
  [[nodiscard]] constexpr T* data() noexcept {
    return std::visit([](auto&& arg) -> T* { return arg.data(); }, var_);
  }

  /** Retrieve the underlying starting iterator of the active variant member. */
  [[nodiscard]] constexpr iterator begin() const noexcept {
    if (std::holds_alternative<std::vector<T>>(var_)) {
      return const_cast<iterator>(
          std::get<std::vector<T>>(var_).begin().base());
    }
    return const_cast<iterator>(std::get<std::array<T, arrSize>>(var_).begin());
  }

  /** Retrieve the underlying ending iterator of the active variant member. */
  [[nodiscard]] constexpr const_iterator end() const noexcept {
    if (std::holds_alternative<std::vector<T>>(var_)) {
      return const_cast<iterator>(std::get<std::vector<T>>(var_).end().base());
    }
    return const_cast<iterator>(std::get<std::array<T, arrSize>>(var_).end());
  }

  /** Retrieve the underlying starting const iterator of the active variant
   * member. */
  [[nodiscard]] constexpr const_iterator cbegin() const noexcept {
    if (std::holds_alternative<std::vector<T>>(var_)) {
      return std::get<std::vector<T>>(var_).cbegin().base();
    }
    return std::get<std::array<T, arrSize>>(var_).cbegin();
  }

  /** Retrieve the underlying ending const iterator of the active variant
   * member. */
  [[nodiscard]] constexpr const_iterator cend() const noexcept {
    if (std::holds_alternative<std::vector<T>>(var_)) {
      return std::get<std::vector<T>>(var_).cend().base();
    }
    return std::get<std::array<T, arrSize>>(var_).cend();
  }

 private:
  /** Variant containing a fixed size array (used by default) and a vector, the
   * latter of which can be utilised by calling addSMEOperand(). */
  std::variant<std::array<T, arrSize>, std::vector<T>> var_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
