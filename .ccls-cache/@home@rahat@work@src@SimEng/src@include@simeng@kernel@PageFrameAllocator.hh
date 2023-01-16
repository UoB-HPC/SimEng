<<<<<<< HEAD
<<<<<<< HEAD
#pragma once
=======
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)
#include <stdint.h>

#include <array>
#include <climits>
#include <cstddef>
<<<<<<< HEAD
<<<<<<< HEAD

#include "simeng/kernel/Constants.hh"

namespace TestFriends {
class PFAFriend;
}

namespace simeng {
namespace kernel {

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
=======
=======
>>>>>>> 76a7cd60 (added pfalloc file)
namespace simeng {
namespace kernel {

struct AllocEntry {
  uint64_t track;
  uint64_t nextFreeAddr;
  uint64_t startAddr_;
  uint64_t size_;
};

class PageFrameAllocator {
 private:
  // supporting a total of 4096 * 64 * 16 KB of frame allocations i.e 4.1GB
  const uint64_t pageSize_ = 4096;
  std::array<AllocEntry*, 4096 * 64> entries_;
  const uint64_t maxAllocEntrySize = pageSize_ * 64;

  uint64_t allocate(size_t size);

 public:
  PageFrameAllocator();
  ~PageFrameAllocator();
  uint64_t allocatePageFrames(size_t size);
<<<<<<< HEAD
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)
};

}  // namespace kernel
}  // namespace simeng
