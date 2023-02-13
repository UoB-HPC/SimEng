#pragma once
#include <iostream>

/** This function checks if a number n is a power of 2. */
template <class T>
static constexpr bool isPow2(const T& n) {
  // Given that n is non-zero, and a power of 2 it can be represented by x bits
  // with only the most significant bit equal to 1 i.e 8 = 0x1000. Subtracting
  // one from n gives a bit pattern with x-1 number of 1s i.e 0x1000 - 0x1 =
  // 0x111. Using 'arithmetic &' on n and (n-1) will give 0 is n is power of 2
  // because of the bit patterns mentioned above. for e.g 0x1000 - 0x111 = 0
  return n && !(n & (n - 1));
}

/**
 * This function is used to transform value such that it is equal to largest
 * multiple of align which is lower than value.
 */
template <class T, class U>
static constexpr T downAlign(const T& val, const U& align) {
  if (!isPow2(align)) {
    std::cerr << "Alignment value is not power of 2" << std::endl;
    std::exit(1);
  }
  // The value of align is a power of 2 and it can be represented by x bits
  // with only the most significant bit equal to 1 i.e 8 = 0x1000. Subtracting
  // one from align gives a bit pattern with x-1 number of 1s
  // i.e 0x1000 - 0x1 = 0x111. Using the "artihmetic &" operation on value and
  // bit reversed mask will convert all x-1 least significant bits of value to
  // 0, hence down aligning value. e.g
  // 56 (0x00111000) down aligned by 16 (0x10000) is 48 (00x00110000)
  // => mask = 16 - 1 => mask = 0x00010000 - 0x1 = 0x00001111
  // => 0x00111000 & ~(0x00001111) => 0x00111000 & 0x11110000 => 0x00110000
  T mask = (T)align - 1;
  return val & ~mask;
}

/**
 * This function is used to transform value such that it is equal to the
 * smallest multiple of align which is greater than value.
 */
template <class T, class U>
static constexpr T upAlign(const T& val, const U& align) {
  if (!isPow2(align)) {
    std::cerr << "Alignment value is not power of 2" << std::endl;
    std::exit(1);
  }
  // The operation to upalign is conceptually similar to down align.
  // However to upalign value we actually down align:
  // y = (value + (align - 1)).
  // y will always be a number than is greater than 1st multiple of
  // 'align' larger than 'value' but less than the 2nd multiple of 'align'
  // larger than 'value'.
  T mask = (T)align - 1;
  return (val + mask) & ~mask;
}
