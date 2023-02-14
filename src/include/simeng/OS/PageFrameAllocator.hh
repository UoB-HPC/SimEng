#pragma once
#include <stdint.h>

#include <array>
#include <climits>
#include <cstddef>

#include "simeng/kernel/Constants.hh"

namespace TestFriends {
class PFAFriend;
}

namespace simeng {
namespace OS {

using namespace simeng::kernel::defaults;

class PageFrameAllocator {
  friend class TestFriends::PFAFriend;

 public:
  /** Maximum size that can be allocated to page frames. */
  const uint64_t maxAllocationSize_ = 0;

  PageFrameAllocator(uint64_t maxSize);

  ~PageFrameAllocator();
  /** Public method to allocate page franes, */
  uint64_t allocate(size_t size);

  /** Method which returns the start address of the next free page frame. */
  uint64_t getNextFreeAddr() { return nextFreeAddr_; };

  /** Method which returns the size left for allocations in memory. */
  uint64_t getSizeLeft() { return sizeLeft_; };

 private:
  /** Unallocated portion of the memory. */
  uint64_t sizeLeft_ = 0;

  /** Address of the next free page frame address. */
  uint64_t nextFreeAddr_ = 0;
};

}  // namespace OS
}  // namespace simeng
