#pragma once
#include <stdint.h>

#include <cstddef>
#include <memory>

#include "simeng/OS/Vma.hh"

namespace simeng {
namespace OS {

class MemRegion {
 public:
  MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t memSize,
            uint64_t stackPtr, uint64_t heapStart, uint64_t pageSize,
            uint64_t mmapStart);
  MemRegion(){};
  ~MemRegion(){};

 private:
  /** Size of the process stack region. */
  size_t stackSize_;
  /** Size of the process heap region. */
  size_t heapSize_;
  /** Size of whole global memory. */
  size_t memSize_;
  /** address of the stack pointer after auxiliary vector has been populated. */
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

  VirtualMemoryArea* stack_vm_ = NULL;
  VirtualMemoryArea* heap_vm_ = NULL;
  VirtualMemoryArea* ptload_vm_ = NULL;

  VirtualMemoryArea* vm_head_;
  size_t vm_size_ = 0;

  /** This method calculates the maximum heap address.*/
  uint64_t calculateMaxHeapAddr();

  uint64_t addMmapVMA(VMA* vma);
  int64_t removeMmapVMA(uint64_t addr, uint64_t length);
  void freeVma();
  void addInitalVMA(char* data, uint64_t startAddr, size_t size, VMAType type);

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
  uint64_t mmapRegion(uint64_t addr, uint64_t length, int prot, int flags,
                      HostFileMMap* hfmmap);
  /** This method unmaps a mmaped region. */
  int64_t unmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                      int flags);

  bool isVmMapped(uint64_t startAddr, size_t size);
  bool overlapsHeapVM(uint64_t addr, size_t size);
  bool overlapsStackVM(uint64_t addr, size_t size);
  bool isPageAligned(uint64_t addr);
};

}  // namespace OS
}  // namespace simeng
