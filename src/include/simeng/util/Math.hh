#pragma once
#include <iostream>

/** This function checks if number 'n' is a power of 2. */
template <class T>
static constexpr bool isPow2(const T& n) {
  //  Given that 'n' is non-zero, and a power of 2, it can be represented by x
  //  bits with only the most significant bit equalling 1 e.g. 8 = 0x1000.
  //  Subtracting one from 'n' gives us a bit of pattern with x-1 number of 1s
  //  e.g. 0x1000 - 1 = 0x111. Using the arithmetic & operation between 'n' and
  //  'n' - 1 will give 0 if 'n' is a power of 2 because there will be no two
  //  ones in same the bit position (for example with the above patterns 0x1000
  //  & 0x0111 = 0x0000). To ensure the edge case of 0 is handled, we then
  //  logical && the logical negation of the result with 'n'. The logical
  //  negotiation of the previous result will be 0 if non-zero and 1 otherwise.
  //  Therefore, when &&'ed with 'n', the return value is only true if the first
  //  result is 0 (representing a power of 2) and 'n' is non-zero.
  return n && !(n & (n - 1));
}

/** This function is used to round 'val' down to the nearest multiple of
 * 'align'. 'align' must be a power of two.*/
template <class T, class U>
static constexpr T downAlign(const T& val, const U& align) {
  if (!isPow2(align)) {
    std::cerr << "[SimEng:Math] Alignment value is not power of 2" << std::endl;
    std::exit(1);
  }
  // Given that the value of align must be a power of 2, it can be represented
  // by x bits with only the most significant bit equalling 1 e.g. 8 = 0x1000.
  // Subtracting one from align gives us a bit of pattern with x-1 number of 1s
  // e.g. 0x1000 - 1 = 0x111. This operation forms our mask for the next step.
  // Using the arithmetic & operation between 'val' and our mask bit reversed,
  // we convert val to be the closest multiple of align less than it. Hence we
  // have "down aligned" val. As an example with
  // T,U = uint8_t
  // val = 61 (0x00111101)
  // align = 16 (0x00010000)
  // mask = 0x00001111
  // ~mask = 0x1111000
  // val & ~mask = 0x00110000 (48)
  T mask = (T)align - 1;
  return val & ~mask;
}

/** This function is used to round 'val' up to the nearest multiple to align.
 * 'align' must be a power of 2. */
template <class T, class U>
static constexpr T upAlign(const T& val, const U& align) {
  if (!isPow2(align)) {
    std::cerr << "[SimEng:Math] Alignment value is not power of 2" << std::endl;
    std::exit(1);
  }
  // The operation of upAlign is very similar to the downAlign function however,
  // we first add the derived mask value to val before "down aligning" it. This
  // ensures that when we "down align" this new value, we get the next multiple
  // of align that is greater than val not less than.
  T mask = (T)align - 1;
  return (val + mask) & ~mask;
}

/***/
template <class T, class U>
static constexpr T pageOffset(const T& val, const U& align) {
  if (!isPow2(align)) {
    std::cerr << "[SimEng:Math] Alignment value is not power of 2" << std::endl;
    std::exit(1);
  }
  T mask = (T)align - 1;
  return (val & mask);
}
