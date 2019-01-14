
#ifndef __H_REGISTER_VALUE
#define __H_REGISTER_VALUE

#include <cassert>
#include <iostream>
#include <memory>

namespace simeng {

/** A class that encapsulates a smart pointer to an arbitrary value, providing
 * casting and data accessor functions. Immutable. */
class RegisterValue {
 public:
  RegisterValue();

  /** Create a RegisterValue from an existing type. */
  RegisterValue(std::shared_ptr<uint8_t> ptr);

  /** Create a new RegisterValue from a value of arbitrary type, zero-extending
   * the allocated memory space to the specified number of bytes (defaulting to
   * the size of the template type). */
  template <class T>
  RegisterValue(T value, uint8_t bytes = sizeof(T)) {
    void* data = calloc(1, bytes);

    T* view = (T*)data;
    view[0] = value;

    this->ptr = std::shared_ptr<uint8_t>(static_cast<uint8_t*>(data), free);
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
    assert(ptr != nullptr &&
           "Attempted to access an uninitialised RegisterValue");
    return reinterpret_cast<T*>(ptr.get());
  }

  /** Check whether this RegisterValue has an assigned value or is null. */
  operator bool() const;

  /** Create a new RegisterValue of size `toBytes`, copying the first
   * `fromBytes` bytes of this one. The remaining bytes of the new RegisterValue
   * are zeroed. */
  RegisterValue zeroExtend(uint8_t fromBytes, uint8_t toBytes) const;

 private:
  /** The underlying pointer each instance references. */
  std::shared_ptr<uint8_t> ptr;
};

}  // namespace simeng

#endif