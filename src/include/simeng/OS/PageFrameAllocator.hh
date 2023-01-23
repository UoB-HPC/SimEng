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
  // supporting a total of 4096 * 64 * 16 KB of frame allocations i.e 4.1GB
  const uint64_t pageSize_ = 4096;
  const uint64_t maxAllocationSize = 2684354560;
  uint64_t sizeLeft = maxAllocationSize;
  uint64_t nextFreeAddr = 0;
  uint64_t allocatePageFrames(size_t size);
  uint64_t populateFrameTrack(uint64_t track, size_t size);

 public:
  PageFrameAllocator();
  ~PageFrameAllocator();
  uint64_t allocate(size_t size);
};

}  // namespace OS
}  // namespace simeng
