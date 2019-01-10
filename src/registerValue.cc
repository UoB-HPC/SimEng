#include "registerValue.hh"

#include <cstring>
#include <iostream>

namespace simeng {

RegisterValue::RegisterValue() { ptr = nullptr; }
RegisterValue::RegisterValue(std::shared_ptr<uint8_t> ptr) : ptr(ptr) {}

RegisterValue RegisterValue::zeroExtend(uint8_t fromBytes,
                                        uint8_t toBytes) const {
  assert(ptr != nullptr &&
         "Attempted to extend an uninitialised RegisterValue");

  auto extended = RegisterValue(0, toBytes);
  std::memcpy(extended.ptr.get(), ptr.get(), fromBytes);
  return extended;
}

}  // namespace simeng
