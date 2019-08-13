#include <array>
#include <iostream>
#include <vector>

namespace simeng {

template <typename T, size_t MaxLocal>
class LocalFirstArray {
 public:
  using pointer = T*;
  using value_type = T;
  using index_type = size_t;
  using reference = T&;
  using iterator = pointer;
  using const_iterator = const T*;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  constexpr LocalFirstArray() : size_(0), local_{} {}
  constexpr LocalFirstArray& operator=(const std::initializer_list<T> list) {
    size_ = list.size();
    if (size_ <= MaxLocal) {
      std::copy(list.begin(), list.end(), local_.begin());
      pointer_ = local_.data();
      return *this;
    }

    fallback_ = list;
    pointer_ = fallback_.data();
    return *this;
  }

  constexpr LocalFirstArray(const LocalFirstArray& other)
      : size_(other.size()) {
    if (size_ <= MaxLocal) {
      std::copy(other.begin(), other.end(), local_.begin());
      pointer_ = local_.data();
      return;
    }

    fallback_.resize(size_);
    std::copy(other.begin(), other.end(), fallback_.begin());
    pointer_ = fallback_.data();
  }
  constexpr LocalFirstArray(size_t size) : size_(size) {}

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

  constexpr void updatePointer() {
    pointer_ = (size_ <= MaxLocal ? local_.data() : fallback_.data());
  }

  constexpr void set(index_type size, value_type value) {
    size_ = size;
    updatePointer();
    if (size <= MaxLocal) {
      pointer_ = local_.data();
    } else {
      fallback_.resize(size_);
      pointer_ = fallback_.data();
    }

    std::fill(begin(), end(), value);
  }

 private:
  index_type size_;
  std::array<value_type, MaxLocal> local_;
  std::vector<value_type> fallback_;

  pointer pointer_;
};

}  // namespace simeng
