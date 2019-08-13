#pragma once

#include <array>
#include <vector>

namespace simeng {

/** A container which stores data in statically-allocated memory where possible,
 * falling back to dynamically allocated memory when too many elements (>
 * `MaxLocal`) are present.
 *
 * This provides greater performance than a std::vector when instances are
 * expected to hold fewer than `MaxLocal` elements the majority of the time, as
 * it prevents costly dynamic memory allocations, at the cost of cheaper static
 * allocation. Profiling may be required to find the optimal `MaxLocal` value
 * for each use case. */
template <typename T, size_t MaxLocal>
class StaticFirstArray {
 public:
  using pointer = T*;
  using value_type = T;
  using index_type = size_t;
  using reference = T&;
  using iterator = pointer;
  using const_iterator = const T*;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  /** Create a zero-size static-first array. */
  constexpr StaticFirstArray() { resize(0); }

  /** Create a static-first array of size `size`. */
  constexpr StaticFirstArray(size_t size) { resize(size); }

  /** Copy-construct a static-first array. */
  constexpr StaticFirstArray(const StaticFirstArray& other) {
    resize(other.size_);
    std::copy(other.begin(), other.end(), begin());
  }

  /** Copy-assign a static-first array. */
  constexpr StaticFirstArray& operator=(const StaticFirstArray& other) {
    resize(other.size_);
    std::copy(other.begin(), other.end(), begin());
    return *this;
  }

  /** Assign the contents of the supplied initialiser list to this array. */
  constexpr StaticFirstArray& operator=(const std::initializer_list<T> list) {
    resize(list.size());
    std::copy(list.begin(), list.end(), begin());
    return *this;
  }

  /** Retrieve the size of the container. */
  constexpr index_type size() const { return size_; }

  /** Check whether the container is empty. */
  [[nodiscard]] constexpr bool empty() const noexcept { return size() == 0; }

  /** Retrieve an iterator at the start of the container. */
  constexpr iterator begin() const noexcept { return pointer_; }

  /** Retrieve a const iterator at the start of the container. */
  constexpr const_iterator cbegin() const noexcept { return begin(); }

  /** Retrieve a reverse iterator at the start of the container. */
  constexpr reverse_iterator rbegin() const noexcept {
    return reverse_iterator(end());
  }

  /** Retrieve a const reverse iterator at the start of the container. */
  constexpr const_reverse_iterator crbegin() const noexcept {
    return const_reverse_iterator(cend());
  }

  /** Retrieve an iterator at the end of the container. */
  constexpr iterator end() const noexcept { return pointer_ + size_; }

  /** Retrieve a const iterator at the end of the container. */
  constexpr const_iterator cend() const noexcept { return end(); }

  /** Retrieve a reverse iterator at the end of the container. */
  constexpr reverse_iterator rend() const noexcept {
    return reverse_iterator(begin());
  }

  /** Retrieve a const reverse iterator at the end of the container. */
  constexpr const_reverse_iterator crend() const noexcept {
    return const_reverse_iterator(cbegin());
  }

  /** Retrieve a reference to the first element of the container. */
  constexpr reference front() const { return pointer_[0]; }

  /** Retrieve a reference to the last element of the container. */
  constexpr reference back() const { return pointer_[size_ - 1]; }

  /** Retrieve a pointer to the container data. */
  constexpr pointer data() const noexcept { return pointer_; }

  /** Retrieve a reference to the element at the supplied index. */
  constexpr reference operator[](index_type idx) const {
    return pointer_[idx];
  };

  /** Resize the array.
   *
   * NOTE: If the new size results in a different memory region being used
   * (static to dynamic, or vice-versa), the previous contents will become
   * inaccessible. It may be safer to always consider this a destructive action.
   */
  constexpr void resize(index_type size) {
    size_ = size;

    if (size_ <= MaxLocal) {
      pointer_ = local_.data();
      return;
    }

    fallback_.resize(size_);
    pointer_ = fallback_.data();
  }

 private:
  /** The current of the container. */
  index_type size_;

  /** The statically allocated memory; used when `size_ <= MaxLocal` */
  std::array<value_type, MaxLocal> local_;

  /** The dynamically allocated memory; used when `size_ > MaxLocal` */
  std::vector<value_type> fallback_;

  /** A pointer to the start of the currently used container. */
  pointer pointer_;
};

}  // namespace simeng
