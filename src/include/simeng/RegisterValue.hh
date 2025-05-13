
#pragma once

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>

#include "simeng/Pool.hh"

namespace simeng {

inline Pool pool = Pool();

/** Global memory pool used by RegisterValue class. */
extern Pool pool;

template <typename T>
struct safePointer {
  // public:
  //  safePointer(const char* ptr) : ptr(ptr) {}

  T operator[](const int i) const {
    T output;
    memcpy(&output, ptr + (i * sizeof(T)), sizeof(T));
    return output;
  }

  // private:
  const uint8_t* ptr;
};


/** A class that holds an arbitrary region of immutable data, providing
 * casting and data accessor functions. For values smaller than or equal to
 * `MAX_LOCAL_BYTES`, this data is held in a local value, otherwise memory is
 * allocated and the data is stored there. */
class RegisterValue {
 public:
  RegisterValue();

  /** Create a new RegisterValue from a value of arbitrary type (except
   * pointers), zero-extending the allocated memory space to the specified
   * number of bytes (defaulting to the size of the template type). */
  template <class T,
            typename std::enable_if_t<!std::is_pointer_v<T>, T>* = nullptr>
  RegisterValue(T value, uint16_t bytes = sizeof(T)) : bytes(bytes) {
    // Ensure the high bits are zeroed
    size_t numBytesToCopy = bytes;
    if (bytes > sizeof(T)) {
      numBytesToCopy = sizeof(T);
    }

    if (isLocal()) {
      memcpy(this->localValue, &value, numBytesToCopy);
    } else {
      uint8_t* data = static_cast<uint8_t*>(pool.allocate(bytes));
      std::memset(data, 0, bytes);
      memcpy(data, &value, numBytesToCopy);

      this->ptr = std::shared_ptr<uint8_t>(
          data, [bytes](uint8_t* ptr) { pool.deallocate(ptr, bytes); });
    }
  }

  /** Create a new RegisterValue of size `capacity`, copying `bytes`
   * from `ptr`.
   */
  RegisterValue(const uint8_t* ptr, uint16_t bytes, uint16_t capacity)
      : bytes(capacity) {
    assert(capacity >= bytes && "Capacity is less than requested bytes");
    uint8_t* dest;
    if (isLocal()) {
      dest = this->localValue;
    } else {
      dest = static_cast<uint8_t*>(pool.allocate(capacity));
      std::memset(dest, 0, capacity);
      this->ptr = std::shared_ptr<uint8_t>(
          dest, [capacity](void* ptr) { pool.deallocate(ptr, capacity); });
    }
    assert(dest && "Attempted to dereference a NULL pointer");
    std::memcpy(dest, ptr, bytes);
  }

  /** Create a new RegisterValue of size `bytes`, copying data from `ptr`. */
  RegisterValue(const uint8_t* ptr, uint16_t bytes)
      : RegisterValue(ptr, bytes, bytes) {}

  /** Create a new RegisterValue by copying bytes from a fixed-size array. The
   * resultant RegisterValue will have size `C` (defaulting to the no. of
   * bytes in the array).
   */
  template <class T, size_t N>
  RegisterValue(T (&array)[N], size_t C = N * sizeof(T))
      : RegisterValue(reinterpret_cast<const uint8_t*>(array), sizeof(T) * N,
                      C) {}

  /** Read the encapsulated raw memory as a specified datatype. */
  template <class T>
  T get() const {
    return getAsVector<T>()[0];
  }

  /** Retrieve a pointer to the encapsulated raw memory, reinterpreted as
   * the specified datatype. */
  template <class T>
  safePointer<T> getAsVector() const {
    static_assert(alignof(T) <= 8 && "Alignment over 8 bytes not guaranteed");
    assert(bytes > 0 && "Attempted to access an uninitialised RegisterValue");
    assert(sizeof(T) <= bytes &&
           "Attempted to access a RegisterValue as a datatype larger than the "
           "data held");
    if (isLocal()) {
      return safePointer<T>{this->localValue};
      // return reinterpret_cast<const T*>(localValue);
    } else {
      return safePointer<T>{ptr.get()};
    }
  }

  /** Retrieve the number of bytes stored. */
  constexpr size_t size() const { return bytes; }

  /** Check whether this RegisterValue has an assigned value or is empty. */
  operator bool() const;

  /** Create a new RegisterValue of size `toBytes`, copying the first
   * `fromBytes` bytes of this one. The remaining bytes of the new
   * RegisterValue are zeroed. */
  RegisterValue zeroExtend(uint16_t fromBytes, uint16_t toBytes) const;

 private:
  /** Check whether the value is held locally or behind a pointer. */
  constexpr bool isLocal() const { return bytes <= MAX_LOCAL_BYTES; }

  /** The maximum number of bytes that can be held locally. */
  static constexpr uint16_t MAX_LOCAL_BYTES = 16;

  /** The number of bytes held. */
  uint16_t bytes = 0;

  /** The underlying pointer each instance references. */
  std::shared_ptr<uint8_t> ptr;

  /** The underlying local member value. Aligned to 8 bytes to prevent
   * potential alignment issue when casting. */
  alignas(8) uint8_t localValue[MAX_LOCAL_BYTES] = {};
};

inline bool operator==(const RegisterValue& lhs, const RegisterValue& rhs) {
  if (lhs.size() == rhs.size()) {
    auto lhV = lhs.getAsVector<uint8_t>();
    auto rhV = rhs.getAsVector<uint8_t>();
    for (size_t i = 0; i < lhs.size(); i++) {
      if (lhV[i] != rhV[i]) return false;
    }
    return true;
  }
  return false;
}

}  // namespace simeng