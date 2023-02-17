#pragma once
#include <stdint.h>

#include <array>
#include <climits>
#include <cstddef>

#include "simeng/OS/Constants.hh"

namespace TestFriends {
class PFAFriend;
}

namespace simeng {
namespace OS {

using namespace simeng::OS::defaults;

class PageFrameAllocator {
 public:
  /* Constructor to create an empty PageFrameAllocator */
  PageFrameAllocator() : maxAllocationSize_(0) {}

  /** Constructor to create a PageFrameAllocator of size 'maxSize'. */
  PageFrameAllocator(uint64_t maxSize);

  ~PageFrameAllocator(){};

  /** Maximum size that can be allocated to page frames. */
  uint64_t maxAllocationSize_;

  /** This method is used to allocate page frames, it returns the start address
   * of a newly allocated page frame of fixed size (4096 bytes). */
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
