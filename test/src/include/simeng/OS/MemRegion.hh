#pragma once
#include <stdint.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>

#include "simeng/OS/Constants.hh"
#include "simeng/OS/Vma.hh"
#include "simeng/Range.hh"

namespace simeng {
namespace OS {

using namespace simeng::OS::defaults;

/** The MemoryRegion class is associated with the Process class and holds
 * memory related state variables for the process class. It is also responsible
 * for handling syscalls to heap and mmap memory regions.  */

typedef std::function<uint64_t(uint64_t, size_t)> RemovePageTableMappingFn;

class MemRegion {
 public:
  /** This constructor creates a MemRegion with values specified by the owning
   * process. */
  MemRegion(uint64_t brk, uint64_t mmapBase, uint64_t mmapEnd,
            uint64_t stackGuardAddr, uint64_t processImgSize,
            RemovePageTableMappingFn fn);

  MemRegion(std::function<uint64_t(uint64_t, size_t)> unmapPageTable);

  /** This constructor creates an empty MemRegion.*/
  MemRegion(){};

  /** Explicit declaration of the default copy constructor. */
  MemRegion(const MemRegion&) = default;

  ~MemRegion();

  /** This method returns the initial heap pointer.*/
  uint64_t getHeapStart() const;

  /** This method returns the heap end address. */
  uint64_t getHeapEnd() const;

  /** This method returns the heap size. */
  size_t getHeapSize() const;

  /** This method returns the current heap pointer. */
  uint64_t getBrk() const;

  /** This method returns the start address of the mmap region.*/
  uint64_t getMmapBase() const;

  /** This method returns the size of the process image.*/
  uint64_t getProcessImgSize() const;

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
  // bool overlapsStack(uint64_t addr, size_t size);

  std::list<VirtualMemoryArea>::iterator findVmaNext(uint64_t startAddr,
                                                     size_t size);

  /** This method retrieves the VMA containing addr. */
  VirtualMemoryArea getVMAFromAddr(uint64_t addr);

  /** This method returns the shared_ptr to the VMAlist. */
  std::list<VirtualMemoryArea>& getVmaList();

  /** This method retrieves the VMA head. */
  VirtualMemoryArea getVMAHead() {
    if (!VMAlist_.size()) {
      return VirtualMemoryArea{};
    }
    return VMAlist_.front();
  }

  /** This method gets the VMA size. */
  size_t getVMASize() { return VMAlist_.size(); }

  void printVmaList();

 private:
  uint64_t brk_;

  uint64_t brkStart_;

  uint64_t mmapBase_;

  uint64_t mmapEnd_;

  uint64_t stackGuardAddr_;

  /** Size of the process image. */
  uint64_t addressSpaceSize_;

  /** Function reference to unmap the page table in removeVma. */
  RemovePageTableMappingFn removePTMapping_;

  /** Shared_ptr to VMA linked list which contains all mmaped virtual memory
   * areas. */
  std::list<VirtualMemoryArea> VMAlist_;

  /** Method to add VMA to the VMA list at the specified start address. If the
   * startAddr is 0 the algorithm will find an optimal address range for the
   * new VMA and return the start address of that range. It is also possible
   * that the address range specified by the startAddr does not have enough
   * space to hold the new VMA, in this case the algorithm will look for a new
   * address range capable to accomodating the new VMA and return its start
   * address. */
  uint64_t addVma(VMA vma, uint64_t startAddr = 0);

  uint64_t addVmaExactlyAtAddr(VMA vma, uint64_t startAddr);

  /** Method to remove VMAs. This method returns the combined size of all VMAs
   * that were removed. A return value of 0 does not signify an error.*/
  int64_t removeVma(uint64_t addr, uint64_t length);
};

}  // namespace OS
}  // namespace simeng
