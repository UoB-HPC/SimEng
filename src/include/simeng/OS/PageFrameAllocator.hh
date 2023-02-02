#pragma once
#include <stdint.h>

#include <array>
#include <climits>
#include <cstddef>

namespace TestFriends {
class PFAFriend;
}

namespace simeng {
namespace OS {

class PageFrameAllocator {
  friend class TestFriends::PFAFriend;

 private:
  /** Unallocated portion of the memory. */
  uint64_t sizeLeft_ = 0;
  /** Address of the next free page frame address. */
  uint64_t nextFreeAddr_ = 0;

 public:
  /** page frame size, defaults to 4096. */
  const uint64_t pageSize_ = 4096;
  /** Maximum size that can be allocated to page frames. */
  const uint64_t maxAllocationSize_ = 0;

  PageFrameAllocator(uint64_t maxSize, uint64_t pageSize = 4096);

  ~PageFrameAllocator();
  /** Public method to allocate page franes, */
  uint64_t allocate(size_t size);

  /** Method which returns the start address of the next free page frame. */
  uint64_t getNextFreeAddr() { return nextFreeAddr_; };

  /** Method which returns the size left for allocations in memory. */
  uint64_t getSizeLeft() { return sizeLeft_; };
};

}  // namespace OS
}  // namespace simeng
