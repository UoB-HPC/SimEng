#pragma once
<<<<<<< HEAD
<<<<<<< HEAD
#include <stdint.h>

#include <cstddef>
#include <functional>
#include <memory>

#include "simeng/kernel/Constants.hh"
=======
=======
>>>>>>> 76a7cd60 (added pfalloc file)

#include <stdint.h>

#include <cstddef>
#include <memory>

<<<<<<< HEAD
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)
#include "simeng/kernel/Vma.hh"

namespace simeng {
namespace kernel {

<<<<<<< HEAD
<<<<<<< HEAD
using namespace simeng::kernel::defaults;

class MemRegion {
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
  
  /** Start of the mmap region. */
  uint64_t mmapStart_;
  
  /** End of the mmap region. */
  uint64_t mmapEnd_;
  
  /** Address of the current mmap region. */
  uint64_t mmapPtr_;
  
  /** Size of the mmap region. */
  size_t mmapSize_;
  
  /** Function reference to unmap the page table in removeVma. */
  std::function<uint64_t(uint64_t, size_t)> unmapPageTable_;
  
  /** Head of the VMA list. */
  VirtualMemoryArea* vm_head_ = nullptr;
  
  /** Size of the VMA list. */
  size_t vm_size_ = 0;

  /** Method to add VMA to the VMA list at the specified start address. */
  uint64_t addVma(VMA* vma, uint64_t startAddr = 0);

  /** Method to remove VMAs */
  int64_t removeVma(uint64_t addr, uint64_t length);

  /** Method to remove the entire VmaList. */
  void removeVmaList();

 public:
  MemRegion(
      uint64_t stackSize, uint64_t heapSize, uint64_t mmapSize,
      uint64_t memSize, uint64_t stackStart, uint64_t heapStart,
      uint64_t mmapStart, uint64_t initStackPtr,
      std::function<uint64_t(uint64_t, size_t)> unmapPageTable =
          [](uint64_t, size_t) -> uint64_t { return 0; });

  MemRegion(){};

  ~MemRegion() { removeVmaList(); };

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
=======
=======
>>>>>>> 76a7cd60 (added pfalloc file)
class Process;

class MemRegion {
  friend class Process;

 public:
  MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t memSize,
            uint64_t stackStart, uint64_t startBrk, uint64_t pageBytes,
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

  VMA* stack_vm_ = NULL;
  VMA* heap_vm_ = NULL;
  VMA* ptload_vm_ = NULL;

  VMA* vm_head_;
  size_t vm_size_ = 0;

  /** This method calculates the maximum heap address.*/
  uint64_t calculateMaxHeapAddr();

  /*
  uint64_t addMmapVMA(VMA* vma);
  int64_t removeMmapVMA(uint64_t addr, uint64_t length);
  void freeVma();
  void addInitalVMA(char* data, uint64_t startAddr, size_t size, VMAType type);
  */

 public:
  /** This method returns the stack size.*/
  uint64_t getStackSize() const;

  /** This method returns the heap size.*/
  uint16_t getHeapSize() const;

  /** This method returns the initial stack pointer.*/
  uint64_t getInitialStackStart() const;
<<<<<<< HEAD
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)

  /** This method returns the current heap pointer. */
  uint64_t getBrk() const;

<<<<<<< HEAD
<<<<<<< HEAD
=======
  /** This method returns the initial heap pointer.*/
  uint64_t getBrkStart() const;

>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
  /** This method returns the initial heap pointer.*/
  uint64_t getBrkStart() const;

>>>>>>> 76a7cd60 (added pfalloc file)
  /** This method returns the start address of the mmap region.*/
  uint64_t getMmapStart() const;

  /** This method returns the size of the global memory.*/
  uint64_t getMemSize() const;

  /** This method updates the heap pointer with a new value. */
  uint64_t updateBrkRegion(uint64_t newBrk);

  /** This method allocates a new mmap region. */
<<<<<<< HEAD
<<<<<<< HEAD
  int64_t mmapRegion(uint64_t addr, uint64_t length, int prot, int flags,
                     HostFileMMap* hfmmap);
  /** This method unmaps a mmaped region. */
  int64_t unmapRegion(uint64_t addr, uint64_t length);

  /** This method checks the startAddr is already mapped in a VM. */
  bool isVmMapped(uint64_t startAddr, size_t size);

  /** This method checks if addr overlaps with heap region. */
  bool overlapsHeap(uint64_t addr, size_t size);

  /** This method checks if addr overlaps with stack region. */
  bool overlapsStack(uint64_t addr, size_t size);

  /** This method retrieves the VMA containing addr. */
  VirtualMemoryArea* getVMAFromAddr(uint64_t addr);

  /** This methof retrievs the VMA head. */
  VirtualMemoryArea* getVMAHead() { return vm_head_; };

  /** This method gets the VMA size. */
  size_t getVMASize() { return vm_size_; }
};
=======
=======
>>>>>>> 76a7cd60 (added pfalloc file)
  uint64_t mmapRegion(uint64_t addr, uint64_t length, int prot, int flags,
                      HostFileMMap* hfmmap);
  /** This method unmaps a mmaped region. */
  int64_t unmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                      int flags);
  /*
  bool isVmMapped(uint64_t startAddr, size_t size);
  bool overlapsHeapVM(uint64_t addr, size_t size);
  bool overlapsStackVM(uint64_t addr, size_t size);
  bool isPageAligned(uint64_t addr);
  */
<<<<<<< HEAD
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)

}  // namespace kernel
}  // namespace simeng
