#pragma once
#include <stdint.h>

#include <cstddef>
#include <functional>
#include <memory>

#include "simeng/OS/Vma.hh"

namespace simeng {
namespace OS {

class MemRegion {
 public:
  MemRegion(
      uint64_t stackSize, uint64_t heapSize, uint64_t mmapSize,
      uint64_t memSize, uint64_t pageSize, uint64_t stackStart,
      uint64_t heapStart, uint64_t mmapStart, uint64_t initStackPtr,
      std::function<uint64_t(uint64_t, size_t)> unmapPageTable =
          [](uint64_t, size_t) -> uint64_t { return 0; });
  MemRegion(){};
  ~MemRegion() { freeVma(); };

 private:
  /** Start address of the stack. */
  uint64_t stackStart_;
  /** End address of the stack. */
  uint64_t stackEnd_;
  /** Size of the process stack region. */
  size_t stackSize_;
  /** address of the stack pointer after auxiliary vector has been populated. */
  uint64_t initStackPtr_;
  /** Start address of the process heap. */
  uint64_t heapStart_;
  /** End address of the process heap. */
  uint64_t heapEnd_;
  /** Size of the process heap region. */
  size_t heapSize_;
  /** Current end address of the process heap. */
  uint64_t brk_;
  /** Size of whole global memory. */
  size_t memSize_;
  /** Page size of the current memory system. */
  uint64_t pageSize_;
  /** Start of the mmap region. */
  uint64_t mmapStart_;
  /** End of the mmap region. */
  uint64_t mmapEnd_;
  /** Address of the current mmap region. */
  uint64_t mmapPtr_;
  /** Size of the mmap region. */
  size_t mmapSize_;

  std::function<uint64_t(uint64_t, size_t)> unmapPageTable_;

  VirtualMemoryArea* vm_head_ = NULL;
  size_t vm_size_ = 0;

  uint64_t addVma(VMA* vma);
  uint64_t addVma(VMA* vma, uint64_t startAddr);
  int64_t removeVma(uint64_t addr, uint64_t length);
  void freeVma();
  void addInitalVMA(char* data, uint64_t startAddr, size_t size, VMAType type);

 public:
  /** This method returns the stack start address. */
  uint64_t getStackStart() const;

  /** This method returns the stack end address. */
  uint64_t getStackEnd() const;

  /** This method returns the stack size.*/
  size_t getStackSize() const;

  /** This method returns the initial stack pointer.*/
  uint64_t getInitialStackPtr() const;

  /** This method returns the initial heap pointer.*/
  uint64_t getHeapStart() const;

  /** This method returns the heap end address. */
  uint64_t getHeapEnd() const;

  /** This method returns the heap size. */
  size_t getHeapSize() const;

  /** This method returns the current heap pointer. */
  uint64_t getBrk() const;

  /** This method returns the start address of the mmap region.*/
  uint64_t getMmapStart() const;

  /** This method returns the size of the global memory.*/
  uint64_t getMemSize() const;

  /** This method updates the heap pointer with a new value. */
  uint64_t updateBrkRegion(uint64_t newBrk);

  /** This method allocates a new mmap region. */
  int64_t mmapRegion(uint64_t addr, uint64_t length, int prot, int flags,
                     HostFileMMap* hfmmap);
  /** This method unmaps a mmaped region. */
  int64_t unmapRegion(uint64_t addr, uint64_t length);

  bool isVmMapped(uint64_t startAddr, size_t size);
  bool overlapsHeap(uint64_t addr, size_t size);
  bool overlapsStack(uint64_t addr, size_t size);
  bool isPageAligned(uint64_t addr);
  VirtualMemoryArea* getVMAFromAddr(uint64_t addr);
  VirtualMemoryArea* getVMAHead() { return vm_head_; };
  size_t getVMASize() { return vm_size_; }
};

}  // namespace OS
}  // namespace simeng
