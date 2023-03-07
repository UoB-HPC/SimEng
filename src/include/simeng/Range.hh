#pragma once
#include <cstdint>
#include <type_traits>

namespace simeng {

/** Templated struct which represents an arithmetic range. */
template <typename T>
struct Range {
  /** Start of the range. */
  T start;

  /** End of the range. */
  T end;

  /** Size of the range. */
  T size;

  /** Constructor which creates the Range struct with specific values. */
  Range(T s, T e, T sz) {
    // Static assert which checks if the template type is an arithmetic type.
    static_assert(std::is_arithmetic_v<T>,
                  "Range should be declared with an arithmetic type");
    start = s;
    end = e;
    size = sz;
  }

  /** Empty constructor for the Range struct. */
  Range() : start(0), end(0), size(0) {}

  /** operator== overload which compares two Range structs. */
  virtual bool operator==(const Range& range) {
    return (start == range.start) && (end == range.end);
  }

  /** This function checks if Range contains another Range. */
  virtual bool contains(const Range& range) {
    return (start <= range.start) && (end > range.end);
  }

  /** This function checks if the range specified by start (s) and size (sz) is
   * contained inside the range of the Range struct. */
  virtual bool contains(T s, T sz) {
    T e = s + sz;
    return (start <= s) && (end > e);
  }

  /** This function checks if Range overlaps with another Range. */
  virtual bool overlaps(const Range& range) {
    return (start < range.end) && (end >= range.start) && (range.size != 0);
  }

  /** This function checks if the range specified by start (s) and size (sz)
   * overlaps with the range of the Range struct. */
  virtual bool overlaps(T s, T sz) {
    T e = s + sz;
    return (start < e) && (end >= s) && (sz != 0);
  }
};

}  // namespace simeng
