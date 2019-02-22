
#pragma once

#include <cassert>
#include <memory>

namespace simeng {

/** A class that holds an arbitrary region of immitable data, providing casting
 * and data accessor functions. For values smaller than or equal to `threshold`,
 * this data is held in a local value, otherwise memory is allocated and the
 * data is stored there. */
class RegisterValue {
 public:
  RegisterValue();

  /** Create a RegisterValue from an existing type. */
  RegisterValue(std::shared_ptr<char> ptr, uint8_t bytes);

  /** Create a new RegisterValue from a value of arbitrary type, zero-extending
   * the allocated memory space to the specified number of bytes (defaulting to
   * the size of the template type). */
  template <class T>
  RegisterValue(T value, uint8_t bytes = sizeof(T)) : bytes(bytes) {
    if (isLocal()) {
      T* view = reinterpret_cast<T*>(this->value);
      view[0] = value;
    } else {
      void* data = calloc(1, bytes);

      T* view = reinterpret_cast<T*>(data);
      view[0] = value;

      this->ptr = std::shared_ptr<char>(static_cast<char*>(data), free);
    }
  }

  /** Read the encapsulated raw memory as a specified datatype. */
  template <class T>
  T get() const {
    return *getAsVector<T>();
  }

  /** Retrieve a pointer to the encapsulated raw memory, reinterpreted as the
   * specified datatype. */
  template <class T>
  const T* getAsVector() const {
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

  /** Check whether this RegisterValue has an assigned value or is empty. */
  operator bool() const;

  /** Create a new RegisterValue of size `toBytes`, copying the first
   * `fromBytes` bytes of this one. The remaining bytes of the new RegisterValue
   * are zeroed. */
  RegisterValue zeroExtend(uint8_t fromBytes, uint8_t toBytes) const;

 private:
  /** Check whether the value is held locally or behind a pointer. */
  bool isLocal() const;

  /** The maximum number of bytes that can be held locally. */
  static const uint8_t threshold = 8;

  /** The number of bytes held. */
  uint8_t bytes = 0;

  /** The underlying pointer each instance references. */
  std::shared_ptr<char> ptr;

  /** The underlying local member value. Aligned to 8 bytes to prevent potential
   * alignment issue when casting. */
  alignas(8) char value[threshold];
};

}  // namespace simeng
