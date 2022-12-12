
template <class T>
static constexpr bool isPow2(const T& n) {
  // If n is non-zero, and subtracting one borrows all the way to the MSB
  // and flips all bits, then this is a power of 2.
  return n && !(n & (n - 1));
}

/**
 * This function is used to align addresses in memory.
 *
 * @param val is the address to be aligned.
 * @param align is the alignment. Can only be a power of 2.
 * @return The aligned address. The smallest number divisible
 * by @param align which is greater than or equal to @param val.
 */
template <class T, class U>
static constexpr T roundUp(const T& val, const U& align) {
  if (!isPow2(align)) {
    std::cerr << "Alignment value is not power of 2" << std::endl;
    std::exit(1);
  }
  T mask = (T)align - 1;
  return (val + mask) & ~mask;
}
