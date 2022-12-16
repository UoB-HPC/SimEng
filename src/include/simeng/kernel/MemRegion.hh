#pragma once
#include <stdint.h>

#include <cstddef>
#include <memory>

#include "simeng/kernel/Vma.hh"

namespace simeng {
namespace kernel {

class MemRegion {
 public:
  MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t memSize,
            uint64_t stackStart, uint64_t startBrk, uint64_t pageBytes,
            uint64_t mmapStart);
  MemRegion(){};
  ~MemRegion() { vma_ll.freeVma(); };

 private:
  /** Size of the process stack region. */
  size_t stackSize_;
  /** Size of the process heap region. */
  size_t heapSize_;
  /** Size of whole global memory. */
  size_t memSize_;
  /** initial start address of the process stack. */
  uint64_t initStackStart_;
  /** Start address of the process heap. */
  uint64_t startBrk_;
  /** Current end address of the process heap. */
  uint64_t brk_;
  /** Page size of the current memory system. */
  uint64_t pageSize_;
  /** Start of the mmap region. */
  uint64_t mmapStart_;
  /** Max heap address. */
  uint64_t maxHeapAddr_;
  /** VirtMemArea linked list. */
  Vmall vma_ll;

  uint64_t calculateMaxHeapAddr();

 public:
  uint64_t getStackSize() const;
  uint16_t getHeapSize() const;
  uint64_t getInitialStackStart() const;
  uint64_t getBrk() const;
  uint64_t getBrkStart() const;
  uint64_t getMmapStart() const;
  uint64_t getMemSize() const;
  uint64_t updateBrkRegion(uint64_t newBrk);
  uint64_t mmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                      int flags);
  int64_t unmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                      int flags);
  void setInitialStackStart(uint64_t addr);
};

}  // namespace kernel
}  // namespace simeng