#pragma once
#include <stdint.h>

#include <cstddef>
#include <functional>
#include <list>
#include <memory>

#include "simeng/OS/Constants.hh"
#include "simeng/OS/Vma.hh"

namespace simeng {
namespace OS {

using namespace simeng::OS::defaults;

/** The MemoryRegion class is associated with the Process class and holds
 * memory related state variables for the process class. It is also responsible
 * for handling syscalls to heap and mmap memory regions.  */
class MemRegion {
 public:
  /** This constructor creates a MemRegion with values specified by the owning
   * process. */
  MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t mmapSize,
            uint64_t memSize, uint64_t stackStart, uint64_t heapStart,
            uint64_t mmapStart, uint64_t initStackPtr,
            std::function<uint64_t(uint64_t, size_t)> unmapPageTable);

  /** This constructor creates am empty MemRegion.*/
  MemRegion(){};

  ~MemRegion();

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

  /** This method returns the size of the simulation memory.*/
  uint64_t getMemSize() const;

  /** This method updates the heap pointer with a new value. */
  uint64_t updateBrkRegion(uint64_t newBrk);

  /** This method allocates a new mmap region. */
  int64_t mmapRegion(uint64_t addr, uint64_t length, int prot, int flags,
                     HostFileMMap hfmmap);

  /** This method unmaps a mmaped region. */
  int64_t unmapRegion(uint64_t addr, uint64_t length);

  /** This method checks if the startAddr is already mapped in a VM. */
  bool isVmMapped(uint64_t startAddr, size_t size);

  /** This method checks if an address range starting from address 'addr' of
   * size 'size' overlaps with heap region. */
  bool overlapsHeap(uint64_t addr, size_t size);

  /** This method checks if an address range starting from address 'addr' of
   * size 'size' overlaps with stack region. */
  bool overlapsStack(uint64_t addr, size_t size);

  /** This method retrieves the VMA containing addr. */
  VirtualMemoryArea getVMAFromAddr(uint64_t addr);

  /** This method returns the shared_ptr to the VMAlist. */
  std::shared_ptr<std::list<VirtualMemoryArea>> getVmaList();

  /** This method retrieves the VMA head. */
  VirtualMemoryArea getVMAHead() {
    if (!VMAlist_->size()) {
      return VirtualMemoryArea{};
    }
    return VMAlist_->front();
  };

  /** This method gets the VMA size. */
  size_t getVMASize() { return VMAlist_->size(); }

 private:
  /** Start address of the stack. */
  uint64_t stackStart_;

  /** Upper bound of the process stack region. */
  uint64_t stackEnd_;

  /** Size of the process stack region. */
  size_t stackSize_;

  /** Address of the stack pointer after auxiliary vector has been populated. */
  uint64_t initStackPtr_;

  /** Start address of the process heap region. */
  uint64_t heapStart_;

  /** Upper bound of the process heap region. */
  uint64_t heapEnd_;

  /** Size of the process heap region. */
  size_t heapSize_;

  /** Current end address of the process heap region. This member variable is
   * incremented after brk syscalls and signifies the amount of process heap
   * currently in use. */
  uint64_t brk_;

  /** Size of the entire simulation memory. */
  size_t memSize_;

  /** Start of the process mmap region. */
  uint64_t mmapStart_;

  /** Upper bound of the process mmap region. */
  uint64_t mmapEnd_;

  /** Current end address of process mmap region. */
  uint64_t mmapPtr_;

  /** Size of the mmap region. */
  size_t mmapSize_;

  /** Function reference to unmap the page table in removeVma. */
  std::function<uint64_t(uint64_t, size_t)> unmapPageTable_;

  /** Head of the VMA list. */
  // VirtualMemoryArea* vm_head_ = nullptr;

  std::shared_ptr<std::list<VirtualMemoryArea>> VMAlist_ = nullptr;

  /** Method to add VMA to the VMA list at the specified start address. If the
   * startAddr is 0 the algorithm will find an optimal address range for the
   * new VMA and return the start address of that range. It is also possible
   * that the address range specified by the startAddr does not have enough
   * space to hold the new VMA, in this case the algorithm will look for a new
   * address range capable to accomodating the new VMA and return its start
   * address. */
  uint64_t addVma(VMA vma, uint64_t startAddr = 0);

  /** Method to remove VMAs. This method returns the combined size of all VMAs
   * that were removed. A return value of 0 does not signify an error.*/
  int64_t removeVma(uint64_t addr, uint64_t length);
};

}  // namespace OS
}  // namespace simeng
