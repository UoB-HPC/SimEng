#pragma once

#include <array>
#include <iterator>

namespace simeng {

/** A partial implementation of the C++20 `std::span`. Provides an iterable
 * wrapper around a pointer of type T, with a known number of elements.
 *
 * https://en.cppreference.com/w/cpp/container/span */
template <class T>
class span {
 public:
  using pointer = T*;
  using value_type = T;
  using index_type = size_t;
  using reference = T&;
  using iterator = pointer;
  using const_iterator = const T*;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  constexpr span() noexcept : pointer_(nullptr), size_(0) {}
  constexpr span(pointer ptr, index_type count) : pointer_(ptr), size_(count) {}

  template <std::size_t N>
  constexpr span(std::array<T, N>& arr) : pointer_(arr.data()), size_(N) {}

  constexpr index_type size() const { return size_; }
  [[nodiscard]] constexpr bool empty() const noexcept { return size() == 0; }

  constexpr iterator begin() const noexcept { return pointer_; }
  constexpr const_iterator cbegin() const noexcept { return begin(); }

  constexpr reverse_iterator rbegin() const noexcept {
    return reverse_iterator(end());
  }
  constexpr const_reverse_iterator crbegin() const noexcept {
    return const_reverse_iterator(cend());
  }

  constexpr iterator end() const noexcept { return pointer_ + size_; }
  constexpr const_iterator cend() const noexcept { return end(); }

  constexpr reverse_iterator rend() const noexcept {
    return reverse_iterator(begin());
  }
  constexpr const_reverse_iterator crend() const noexcept {
    return const_reverse_iterator(cbegin());
  }

  constexpr reference front() const { return pointer_[0]; }
  constexpr reference back() const { return pointer_[size_ - 1]; }
  constexpr pointer data() const noexcept { return pointer_; }

  constexpr reference operator[](index_type idx) const {
    return pointer_[idx];
  };

 private:
  T* pointer_;
  index_type size_;
};

}  // namespace simeng
