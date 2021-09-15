
#pragma once

#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>

namespace simeng {

/** A class that holds an arbitrary region of immutable data, providing casting
 * and data accessor functions. For values smaller than or equal to
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
    if (isLocal()) {
      T* view = reinterpret_cast<T*>(this->value);
      view[0] = value;

      if (bytes > sizeof(T)) {
        // Zero the remaining bytes not set by the provided value
        std::fill<char*, uint16_t>(this->value + sizeof(T), this->value + bytes,
                                   0);
      }
    } else {
      void* data = calloc(1, bytes);

      T* view = reinterpret_cast<T*>(data);
      view[0] = value;

      this->ptr = std::shared_ptr<char>(static_cast<char*>(data), free);
    }
  }

  /** Create a new RegisterValue of size `capacity`, copying `bytes`
   * from `ptr`.
   */
  RegisterValue(const char* ptr, uint16_t bytes, uint16_t capacity)
      : bytes(capacity) {
    assert(capacity >= bytes && "Capacity is less then requested bytes");
    char* dest;
    if (isLocal()) {
      dest = this->value;
    } else {
      dest = static_cast<char*>(calloc(1, capacity));
      this->ptr = std::shared_ptr<char>(dest, free);
    }
    assert(dest && "Attempted to dereference a NULL pointer");
    std::memcpy(dest, ptr, bytes);
  }

  /** Create a new RegisterValue of size `bytes`, copying data from `ptr`. */
  RegisterValue(const char* ptr, uint16_t bytes)
      : RegisterValue(ptr, bytes, bytes) {}

  /** Create a new RegisterValue by copying bytes from a fixed-size array. The
   * resultant RegisterValue will have size `C` (defaulting to the no. of bytes
   * in the array).
   */
  template <class T, size_t N>
  RegisterValue(T (&array)[N], size_t C = N * sizeof(T))
      : RegisterValue(reinterpret_cast<const char*>(array), sizeof(T) * N, C) {}

  /** Read the encapsulated raw memory as a specified datatype. */
  template <class T>
  T get() const {
    return *getAsVector<T>();
  }

  /** Retrieve a pointer to the encapsulated raw memory, reinterpreted as
   * the specified datatype. */
  template <class T>
  const T* getAsVector() const {
    static_assert(alignof(T) <= 8 && "Alignment over 8 bytes not guranteed");
    assert(bytes > 0 && "Attempted to access an uninitialised RegisterValue");
    assert(sizeof(T) <= bytes &&
           "Attempted to access a RegisterValue as a datatype larger than the "
           "data held");
    if (isLocal()) {
      return reinterpret_cast<const T*>(value);
    } else {
      return reinterpret_cast<const T*>(ptr.get());
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
  std::shared_ptr<char> ptr;

  /** The underlying local member value. Aligned to 8 bytes to prevent
   * potential alignment issue when casting. */
  alignas(8) char value[MAX_LOCAL_BYTES];
};

}  // namespace simeng