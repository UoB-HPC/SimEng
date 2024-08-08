#include "simeng/RegisterValue.hh"

#include <cstring>

namespace simeng {

Pool pool = Pool();

RegisterValue::RegisterValue() : bytes(0) {}

RegisterValue::operator bool() const { return (bytes > 0); }

RegisterValue RegisterValue::zeroExtend(uint16_t fromBytes,
                                        uint16_t toBytes) const {
  assert(bytes > 0 && "Attempted to extend an uninitialised RegisterValue");
  assert(fromBytes <= bytes &&
         "Attempted to copy more data from a RegisterValue than it held");

  auto extended = RegisterValue(0, toBytes);

  // Get the appropriate source/destination pointers and copy the data
  const char* src = (isLocal() ? value : ptr.get());
  char* dest = (extended.isLocal() ? extended.value : extended.ptr.get());

  std::memcpy(dest, src, fromBytes);

  return extended;
}

RegisterValue RegisterValue::signExtend(uint16_t maxBytes, uint16_t fromBytes,
                                        uint16_t toBytes) const {
  assert(bytes > 0 && "Attempted to extend an uninitialised RegisterValue");
  assert(fromBytes <= bytes &&
         "Attempted to copy more data from a RegisterValue than it held");

  auto full = RegisterValue(0, maxBytes);

  // Get the appropriate source/destination pointers and copy the data
  const char* src = (isLocal() ? value : ptr.get());
  char* dest = (full.isLocal() ? full.value : full.ptr.get());

  // If MSB is 1, extend it
  if (src[fromBytes - 1] & 0x80) {
    auto extended = RegisterValue(-1ull, toBytes);
    const char* ext =
        (extended.isLocal() ? extended.value : extended.ptr.get());
    std::memcpy(dest, ext, toBytes);
  }

  std::memcpy(dest, src, fromBytes);

  return full;
}

}  // namespace simeng
