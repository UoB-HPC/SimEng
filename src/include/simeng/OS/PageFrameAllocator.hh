#include <stdint.h>

#include <array>
#include <climits>
#include <cstddef>
namespace simeng {
namespace OS {

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
};

}  // namespace OS
}  // namespace simeng
