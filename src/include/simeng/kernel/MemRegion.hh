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
  /** This method calculates the maximum heap address.*/
  uint64_t calculateMaxHeapAddr();

 public:
  /** This method returns the stack size.*/
  uint64_t getStackSize() const;

  /** This method returns the heap size.*/
  uint16_t getHeapSize() const;

  /** This method returns the initial stack pointer.*/
  uint64_t getInitialStackStart() const;

  /** This method returns the current heap pointer. */
  uint64_t getBrk() const;

  /** This method returns the initial heap pointer.*/
  uint64_t getBrkStart() const;

  /** This method returns the start address of the mmap region.*/
  uint64_t getMmapStart() const;

  /** This method returns the size of the global memory.*/
  uint64_t getMemSize() const;

  /** This method updates the heap pointer with a new value. */
  uint64_t updateBrkRegion(uint64_t newBrk);

  /** This method allocates a new mmap region. */
  uint64_t mmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                      int flags);
  /** This method unmaps a mmaped region. */
  int64_t unmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                      int flags);
};

}  // namespace kernel
}  // namespace simeng