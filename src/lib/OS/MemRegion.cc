#include "simeng/OS/MemRegion.hh"

#include <bits/stdint-uintn.h>
#include <sys/mman.h>

#include <cassert>
#include <cstdint>
#include <forward_list>
#include <iostream>
#include <iterator>
#include <memory>
#include <vector>

#include "simeng/OS/Constants.hh"
#include "simeng/OS/Vma.hh"
#include "simeng/util/Math.hh"
#include "simeng/util/Optimisations.hh"

namespace simeng {
namespace OS {

using namespace syscalls::mmap::flags;

MemRegion::MemRegion(RemovePageTableMappingFn fn) : removePTMapping_(fn) {}

MemRegion::MemRegion(uint64_t brk, uint64_t mmapBase, uint64_t mmapEnd,
                     uint64_t stackGuardAddr, uint64_t processImgSize,
                     RemovePageTableMappingFn fn)
    : brk_(brk),
      brkStart_(brk),
      mmapBase_(mmapBase),
      mmapEnd_(mmapEnd),
      stackGuardAddr_(stackGuardAddr),
      addressSpaceSize_(processImgSize),
      removePTMapping_(fn) {}

MemRegion::~MemRegion() {}

uint64_t MemRegion::getHeapStart() const { return brkStart_; }

uint64_t MemRegion::getHeapEnd() const { return brk_; }

size_t MemRegion::getHeapSize() const { return brk_ - brkStart_; }

uint64_t MemRegion::getBrk() const { return brk_; }

uint64_t MemRegion::getMmapBase() const { return mmapBase_; }

uint64_t MemRegion::getProcessImgSize() const { return addressSpaceSize_; };
uint64_t MemRegion::updateBrkRegion(uint64_t brk) {
  std::cout << "brk happens" << std::endl;
  // We have to make sure that the binary under simulation isn't trying to
  // deallocate more memory than is present in the process heap region.
  if (brk < brkStart_) {
    if (brk != 0) {
      std::cerr << "[SimEng:MemRegion] Attemped to deallocate more memory than "
                   "is available to the process heap region."
                << std::endl;
    }
    return brk_;
  }

  uint64_t newBrk = upAlign(brk, PAGE_SIZE);
  uint64_t oldBrk = upAlign(brk_, PAGE_SIZE);

  if (oldBrk == newBrk) {
    brk_ = brk;
    return brk;
  }

  if (brk < brk_) {
    /** if (unmapRegion(brk, brk_ - brk) < 0) {
      return brk_;
    }
    */
    brk_ = brk;
    return brk_;
  }

  if (newBrk > stackGuardAddr_) {
    std::cerr << "[SimEng:MemRegion] Attempting to increasing program brake "
                 "beyond stack guard gap."
              << std::endl;
    std::exit(1);
  }

  if (isVmMapped(oldBrk, newBrk - oldBrk)) {
    return brk_;
  }
  mmapRegion(oldBrk, newBrk - oldBrk, 0, SIMENG_MAP_FIXED, HostFileMMap());
  brk_ = brk;

  return brk_;
}

uint64_t MemRegion::addVma(VMA vma, uint64_t startAddr) {
  size_t size = vma.vmSize_;
  auto first = --VMAlist_.rend();
  auto itr = VMAlist_.rbegin();

  if (likely(VMAlist_.size() > 0)) {
    /*
     The VMAlist_ contains all VMAs, including the stack VMA, which resides
     beyond the mmap region. The stack is located at the top of the address
     range. In SimEng, the entire stack is currently mapped as a single VMA.
     Since the VMAList_ is always sorted, the first reverse iterator always
     points to the stack VMA. This iterator should be skipped in the mmap
     algorithm to ensure that no mmap allocations occur between the highest
     address of the mmap region and the lowest address of the stack. However,
     if the MAP_FIXED flag is specified, the allocation can be made anywhere
     within the entire address range: [0, 2^48); So we have make sure
     that we skip all VMA allocations beyond mmap region.
     */
    while (itr != VMAlist_.rend() && itr->vmStart_ >= mmapBase_) {
      itr++;
    }

    uint64_t effStartAddr = startAddr;
    uint64_t space = 0;

    if (!startAddr) {
      effStartAddr = mmapBase_ - size;
      space = mmapBase_ - itr->vmEnd_;

      if (effStartAddr >= itr->vmEnd_ && space >= size) {
        vma.vmStart_ = effStartAddr;
        vma.vmEnd_ = effStartAddr + size;
        VMAlist_.insert(itr.base(), vma);
        return vma.vmStart_;
      }

      startAddr = itr->vmStart_;
    }

    while (itr != first) {
      auto next = std::next(itr, 1);
      uint64_t oldStart = startAddr;
      startAddr = startAddr && startAddr < itr->vmStart_ ? startAddr
                                                         : itr->vmStart_ - size;
      space = itr->vmStart_ - startAddr;
      if (startAddr >= next->vmEnd_ && space >= size) {
        vma.vmStart_ = startAddr;
        vma.vmEnd_ = startAddr + size;
        VMAlist_.insert(next.base(), vma);
        return vma.vmStart_;
      }
      itr = next;
      startAddr = oldStart;
    }

    /*
    It is highly unlikely for us to enter this region of the algorithm
    because during the execution of SimEng, whether it's a binary or regression
    test, there will always be at least three mappings prior to the simulation
    starting. These mappings include PT_LOAD sections from the binary or
    instructions from regression tests, as well as the heap and stack.

    Although it is improbable, there are three scenarios in which we may enter
    this region of the algorithm:

    1) The entire mmap region is heavily congested, and we are compelled to
       search for space in the lower part of the mmap address space.

    2) The user specifies a valid but extremely small startAddr, and we make an
       effort to accommodate the user's request.

    3) During the execution of unit/integration tests, when the process memory
       layout is not defined. In order to ensure functional correctness, we need
       to handle cases where the algorithm cannot find space between
       pre-existing VMAs, even though there is still ample space available in
       the mmap address region.
    */
    startAddr = itr->vmStart_ - size;
    space = startAddr - mmapEnd_;
    if (startAddr < mmapEnd_) {
      // We can't find any space for the new VMA, the entire VMA space is
      // congested and mapped.
      return 0;
    }
    vma.vmStart_ = startAddr;
    vma.vmEnd_ = startAddr + size;
    VMAlist_.push_front(vma);
    return vma.vmStart_;
  }
  // This is the first allocation ever.
  uint64_t space = mmapBase_ - startAddr;
  startAddr = (startAddr) && space >= size ? startAddr : mmapBase_ - size;
  vma.vmEnd_ = startAddr + size;
  vma.vmStart_ = startAddr;
  VMAlist_.push_front(vma);
  return vma.vmStart_;
}

uint64_t MemRegion::addVmaExactlyAtAddr(VMA vma, uint64_t startAddr) {
  size_t size = vma.vmSize_;
  auto last = std::prev(VMAlist_.end(), 1);

  vma.vmStart_ = startAddr;
  vma.vmEnd_ = startAddr + size;

  auto itr = VMAlist_.begin();
  if (VMAlist_.size() && startAddr < itr->vmStart_ &&
      startAddr + size < itr->vmStart_) {
    VMAlist_.push_front(vma);
    return startAddr;
  }

  while (itr != last && itr->vmStart_ < startAddr) {
    auto next = std::next(itr);
    if (next->vmStart_ < startAddr) {
      itr = next;
      continue;
    }
    if (itr->contains(startAddr, size) || itr->overlaps(startAddr, size)) {
      // error MAP_FIXED can't succed cause region is still mapped.
      return -1;
    }

    if (next->vmStart_ - itr->vmEnd_ < size) {
      // error not enough space, this should've been detected before and
      // unmapped
      return -1;
    }
    VMAlist_.insert(next, vma);
    return startAddr;
  }

  if (itr != last) {
    return -1;
  }

  if (last->contains(startAddr, size) || last->overlaps(startAddr, size)) {
    // error MAP_FIXED can't succed cause region is still mapped.
    return -1;
  }

  VMAlist_.push_back(vma);
  return startAddr;
}

int64_t MemRegion::removeVma(uint64_t addr, uint64_t length) {
  uint64_t endAddr = addr + length;
  uint64_t delsize = 0;

  auto itr = VMAlist_.begin();
  for (itr = VMAlist_.begin(); itr != VMAlist_.end();) {
    // If the address range completely contains the current VMA, delete the
    // entire VMA and decrease VMA list size by 1.
    //  [--------Addr--------]
    //      [----VMA ----)
    if (itr->containedIn(addr, length)) {
      delsize += itr->vmSize_;
      itr = VMAlist_.erase(itr);
    }
    // If the address range is within the bounds of the current VMA, split
    // the VMA into two smaller VMAs and increase the VMA list size by 1
    //      [---Addr---]
    // [--------VMA --------)
    else if (itr->contains(addr, length)) {
      if (addr == itr->vmStart_) {
        itr->trimRangeStart(endAddr);
      } else if (endAddr == itr->vmEnd_) {
        itr->trimRangeEnd(addr);
      } else {
        VMA newVma = VMA(*itr);
        itr->trimRangeEnd(addr);
        newVma.trimRangeStart(endAddr);
        // std::list::insert inserts element before the position specified
        // by the iterator. Hence std::next is used to advance the iterator
        // so that the new VMA can be inserted at the correct place.
        VMAlist_.insert(std::next(itr, 1), newVma);
      }
      delsize += length;
      break;
    }
    // If the current VMA overlaps with the address range delete the
    // overlapping region of the VMA.
    //          [--------Addr--------]
    //  [--------VMA --------)
    else if (itr->overlaps(addr, length)) {
      if (addr > itr->vmStart_ && endAddr > itr->vmEnd_) {
        delsize += (itr->vmEnd_ - addr);
        itr->trimRangeEnd(addr);
        itr++;
      } else {
        delsize += (endAddr - itr->vmStart_);
        itr->trimRangeStart(endAddr);
        break;
      }
    } else {
      itr++;
    }
  }

  return delsize;
}

int64_t MemRegion::mmapRegion(uint64_t startAddr, uint64_t length, int prot,
                              int flags, HostFileMMap hfmmap) {
  if (startAddr && startAddr < mmapEnd_) {
    std::cerr << "[SimEng::MemRegion] Start address given to mmapRegion is "
                 "less than mmap_min_addr: "
              << startAddr << std::endl;
    return -1;
  }

  uint64_t size = upAlign(length, PAGE_SIZE);

  uint64_t fixed = flags & syscalls::mmap::flags::SIMENG_MAP_FIXED;
  if (fixed) {
    /**
    if (startAddr == 6791168) {
      startAddr = 6729384;
      startAddr = downAlign(startAddr, PAGE_SIZE);
    }
    */
    if (downAlign(startAddr, PAGE_SIZE) != startAddr) {
      std::cerr << "[SimEng:MemRegion] Addr argument specified with MAP_FIXED "
                   "flag to the mmap call is not page aligned."
                << std::endl;
      return -1;
    }
    if (startAddr + length > addressSpaceSize_) {
      std::cerr << "[SimEng:MemRegion] Addr and length argument specified with "
                   "MAP_FIXED flag to the mmap call exceeds virtual address "
                   "space size available to the process."
                << std::endl;
    }

    if (isVmMapped(startAddr, length)) {
      unmapRegion(startAddr, length);
    }

    VMA vma = VMA(prot, flags, size, hfmmap);
    uint64_t retAddr = addVmaExactlyAtAddr(vma, startAddr);
    /**std::cout << "------------------------------" << std::endl;
    printVmaList();
    std::cout << "------------------------------" << std::endl;*/
    return retAddr;
  }

  if (startAddr + length > stackGuardAddr_) {
    std::cerr << "[SimEng:MemRegion] Address range given to mmapRegion is "
                 "greater than virtual address space"
              << std::endl;
    return -1;
  }

  startAddr = downAlign(startAddr, PAGE_SIZE);
  VMA vma = VMA(prot, flags, size, hfmmap);
  // TODO: Check if offset should be contained in HostBackedFileMMap,
  // because hfmmaps are shared during unmaps.
  uint64_t retAddr = addVma(vma, startAddr);
  /*
  std::cout << "------------------------------" << std::endl;
  printVmaList();
  std::cout << "------------------------------" << std::endl;*/
  return retAddr;
}

int64_t MemRegion::unmapRegion(uint64_t addr, uint64_t length) {
  if (downAlign(addr, 4096) != addr) {
    std::cerr << "[SimEng:MemRegion] Addr provided to unmapRegion not page "
                 "size aligned."
              << std::endl;
    return -1;
  }

  uint64_t size = upAlign(length, PAGE_SIZE);
  uint64_t value = removeVma(addr, size);

  removePTMapping_(addr, size);
  return value;
}

bool MemRegion::isVmMapped(uint64_t addr, size_t size) {
  for (auto itr = VMAlist_.begin(); itr != VMAlist_.end(); itr++) {
    if (itr->contains(addr, size) || itr->overlaps(addr, size)) {
      return true;
    }
  }
  return false;
}

VirtualMemoryArea MemRegion::getVMAFromAddr(uint64_t vaddr) {
  for (auto itr = VMAlist_.begin(); itr != VMAlist_.end(); itr++) {
    if (itr->contains(vaddr)) {
      return *itr;
    }
  }
  return VirtualMemoryArea{};
}

std::list<VirtualMemoryArea>& MemRegion::getVmaList() { return VMAlist_; }

bool MemRegion::overlapsHeap(uint64_t addr, size_t size) {
  uint64_t end = addr + size;
  return end > brkStart_ && brk_ > addr;
}

void MemRegion::printVmaList() {
  auto itr = VMAlist_.begin();
  std::cout << "Vma-list" << std::endl;
  uint16_t count = 1;
  while (itr != VMAlist_.end()) {
    std::cout << "Vma: " << count << std::endl;
    std::cout << "Start: " << std::hex << "0x" << itr->vmStart_ << std::dec
              << " ( " << itr->vmStart_ << " )" << std::endl;
    std::cout << "End: " << std::hex << "0x" << itr->vmEnd_ << std::dec << " ( "
              << itr->vmEnd_ << " )" << std::endl;
    std::cout << "Size: " << std::hex << "0x" << itr->vmSize_ << std::dec
              << " ( " << itr->vmSize_ << " )" << std::endl;
    std::cout << std::endl;
    itr++;
    count++;
  }
}

}  // namespace OS
}  // namespace simeng
