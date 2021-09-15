#include "simeng/RegisterValue.hh"

#include <cstring>

namespace simeng {

RegisterValue::operator bool() const { return (bytes > 0); }

RegisterValue RegisterValue::zeroExtend(uint16_t fromBytes,
                                        uint16_t toBytes) const {
  assert(bytes > 0 && "Attempted to extend an uninitialised RegisterValue");
  assert(fromBytes <= bytes &&
         "Attempted to copy more data from a RegisterValue than it held");

  auto extended = RegisterValue(0, toBytes);

  // Get the appropriate source/destination pointers and copy the data
  const char* src = (isLocal() ? value : ptr);
  char* dest = (extended.isLocal() ? extended.value : extended.ptr);

  std::memcpy(dest, src, fromBytes);

  return extended;
}

}  // namespace simeng
