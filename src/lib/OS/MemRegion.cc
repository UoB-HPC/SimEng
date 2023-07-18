#include "simeng/OS/MemRegion.hh"

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

MemRegion::MemRegion(uint64_t stackEnd, uint64_t stackTop, uint64_t heapStart,
                     uint64_t heapEnd, uint64_t mmapStart, uint64_t mmapEnd,
                     uint64_t initStackPtr,
                     std::function<uint64_t(uint64_t, size_t)> unmapPageTable)
    : stackRegion_(ProcessStackRegion(stackEnd, stackTop, initStackPtr)),
      heapRegion_(std::make_shared<ProcessHeapRegion>(heapStart, heapEnd)),
      mmapRegion_(std::make_shared<ProcessMmapRegion>(mmapStart, mmapEnd)),
      procImgSize_(stackTop),
      unmapPageTable_(unmapPageTable),
      VMAlist_(std::make_shared<std::list<VirtualMemoryArea>>()) {}

MemRegion::MemRegion(std::function<uint64_t(uint64_t, size_t)> unmapPageTable)
    : unmapPageTable_(unmapPageTable),
      VMAlist_(std::make_shared<std::list<VirtualMemoryArea>>()) {}

MemRegion::~MemRegion() {}

uint64_t MemRegion::getStackStart() const { return stackRegion_.stackStart; }

uint64_t MemRegion::getStackEnd() const {
  // Since the stack grows down towards lower addresses, the stack end
  // address is the lowest address in the stack address range. Here
  // stackRegion_.start represents the start of the range, not the actual
  // starting address (topmost address) of the stack.
  return stackRegion_.start;
}

size_t MemRegion::getStackSize() const { return stackRegion_.size; }

uint64_t MemRegion::getInitialStackPtr() const {
  return stackRegion_.initialStackPtr;
}

uint64_t MemRegion::getHeapStart() const { return heapRegion_->start; }

uint64_t MemRegion::getHeapEnd() const { return heapRegion_->end; }

size_t MemRegion::getHeapSize() const { return heapRegion_->size; }

uint64_t MemRegion::getBrk() const { return heapRegion_->brk; }

uint64_t MemRegion::getMmapStart() const { return mmapRegion_->start; }

uint64_t MemRegion::getProcImgSize() const { return procImgSize_; }

uint64_t MemRegion::updateBrkRegion(uint64_t brk) {
  // We have to make sure that the binary under simulation isn't trying to
  // deallocate more memory than is present in the process heap region.
  if (brk < heapRegion_->startBrk) {
    if (brk != 0) {
      std::cerr << "[SimEng:MemRegion] Attemped to deallocate more memory than "
                   "is available to the process heap region."
                << std::endl;
    }
    return heapRegion_->brk;
  }

  uint64_t newBrk = upAlign(brk, PAGE_SIZE);
  uint64_t oldBrk = upAlign(heapRegion_->brk, PAGE_SIZE);

  if (oldBrk == newBrk) {
    heapRegion_->brk = brk;
    return brk;
  }

  if (brk < heapRegion_->brk) {
    uint64_t origBrk = heapRegion_->brk;
    heapRegion_->brk = brk;
    if (unmapRegion(brk, heapRegion_->brk - brk) < 0) {
      heapRegion_->brk = origBrk;
      return origBrk;
    }
    return heapRegion_->brk;
  }

  if (newBrk > heapRegion_->end) {
    std::cerr << "[SimEng:MemRegion] Attemped to allocate more memory on the "
                 "heap than is available to the process. Please increase the "
                 "{Process-Image:{Heap-Size: <size>}} parameter in the YAML "
                 "model config file used to run this simulation."
              << std::endl;
    std::exit(1);
  }

  uint64_t retAddr =
      mmapRegion(newBrk, newBrk - oldBrk, 0, SIMENG_MAP_FIXED, HostFileMMap());
  assert(retAddr == newBrk &&
         "[SimEng:MemRegion] Address returned by mmapRegion with MAP_FIXED flag"
         "returned different address - updateBrk.");
  heapRegion_->brk = brk;

  return brk;
}

void MemRegion::updateStack(const uint64_t stackPtr) {
  VirtualMemoryArea vma = getVMAFromAddr(stackPtr);
  stackRegion_ = ProcessStackRegion(vma.vmStart_, vma.vmEnd_, stackPtr);
}

void MemRegion::setStackRegion(uint64_t stack_top, uint64_t stack_end) {
  stackRegion_ = ProcessStackRegion(stack_end, stack_top, 0);
  procImgSize_ = stack_top;
};

void MemRegion::setHeapRegion(uint64_t heap_start, uint64_t heap_end) {
  if (!heapRegion_) {
    heapRegion_ = std::make_shared<ProcessHeapRegion>(heap_start, heap_end);
  } else {
    heapRegion_->start = heap_start;
    heapRegion_->end = heap_end;
    heapRegion_->size = heap_end - heap_start;
    heapRegion_->startBrk = heap_start;
    heapRegion_->brk = heap_start;
  }
};

void MemRegion::setMmapRegion(uint64_t mmap_start, uint64_t mmap_end) {
  if (!mmapRegion_) {
    mmapRegion_ = std::make_shared<ProcessMmapRegion>(mmap_start, mmap_end);
  } else {
    mmapRegion_->start = mmap_start;
    mmapRegion_->end = mmap_end;
    mmapRegion_->size = mmap_end - mmap_start;
  }
};

uint64_t MemRegion::addVma(VMA vma, uint64_t startAddr) {
  size_t size = vma.vmSize_;
  auto first = --VMAlist_->rend();
  auto itr = VMAlist_->rbegin();

  if (likely(VMAlist_->size() > 0)) {
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
    while (itr != VMAlist_->rend() && itr->vmStart_ >= mmapRegion_->end) {
      itr++;
    }

    uint64_t effStartAddr = startAddr;
    uint64_t space = 0;

    if (!startAddr) {
      effStartAddr = mmapRegion_->end - size;
      space = mmapRegion_->end - itr->vmEnd_;

      if (effStartAddr >= itr->vmEnd_ && space >= size) {
        vma.vmStart_ = effStartAddr;
        vma.vmEnd_ = effStartAddr + size;
        VMAlist_->insert(itr.base(), vma);
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
        VMAlist_->insert(next.base(), vma);
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
    space = startAddr - mmapRegion_->start;
    if (startAddr < mmapRegion_->start) {
      // We can't find any space for the new VMA, the entire VMA space is
      // congested and mapped.
      return 0;
    }
    vma.vmStart_ = startAddr;
    vma.vmEnd_ = startAddr + size;
    VMAlist_->push_front(vma);
    return vma.vmStart_;
  }
  // This is the first allocation ever.
  uint64_t space = mmapRegion_->end - startAddr;
  startAddr =
      (startAddr) && space >= size ? startAddr : mmapRegion_->end - size;
  vma.vmEnd_ = startAddr + size;
  vma.vmStart_ = startAddr;
  VMAlist_->push_front(vma);
  return vma.vmStart_;
}

uint64_t MemRegion::addVmaExactlyAtAddr(VMA vma, uint64_t startAddr) {
  size_t size = vma.vmSize_;
  auto last = std::prev(VMAlist_->end(), 1);

  vma.vmStart_ = startAddr;
  vma.vmEnd_ = startAddr + size;

  auto itr = VMAlist_->begin();
  if (VMAlist_->size() && startAddr < itr->vmStart_) {
    VMAlist_->push_front(vma);
    return startAddr;
  }

  while (itr != last && itr->vmEnd_ <= startAddr) {
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
    VMAlist_->insert(next, vma);
    return startAddr;
  }

  if (last->contains(startAddr, size) || last->overlaps(startAddr, size)) {
    // error MAP_FIXED can't succed cause region is still mapped.
    return -1;
  }
  VMAlist_->push_back(vma);
  return startAddr;
}

int64_t MemRegion::removeVma(uint64_t addr, uint64_t length) {
  uint64_t endAddr = addr + length;
  uint64_t delsize = 0;

  auto itr = VMAlist_->begin();
  for (itr = VMAlist_->begin(); itr != VMAlist_->end();) {
    // If the address range completely contains the current VMA, delete the
    // entire VMA and decrease VMA list size by 1.
    //  [--------Addr--------]
    //      [----VMA ----)
    if (itr->containedIn(addr, length)) {
      delsize += itr->vmSize_;
      itr = VMAlist_->erase(itr);
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
        VMAlist_->insert(std::next(itr, 1), newVma);
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
  if (startAddr + length > stackRegion_.end) {
    std::cerr << "[SimEng:MemRegion] Address range given to mmapRegion is "
                 "greater than virtual address space"
              << std::endl;
    return -1;
  }

  // mmap_min_addr
  if (startAddr && startAddr < PAGE_SIZE) {
    std::cerr << "[SimEng::MemRegion] Start address given to mmapRegion is "
                 "less than mmap_min_addr: "
              << startAddr << std::endl;
    return -1;
  }

  uint64_t size = upAlign(length, PAGE_SIZE);

  uint64_t fixed = flags & syscalls::mmap::flags::SIMENG_MAP_FIXED;

  if (fixed) {
    if (downAlign(startAddr, PAGE_SIZE) != startAddr) {
      std::cerr << "Addr argument specified with MAP_FIXED flag to the mmap "
                   "call is not page aligned."
                << std::endl;
      return -1;
    }

    if (isVmMapped(startAddr, length)) {
      unmapRegion(startAddr, length);
    }

    VMA vma = VMA(prot, flags, size, hfmmap);
    uint64_t retAddr = addVmaExactlyAtAddr(vma, startAddr);
    return retAddr;
  }

  startAddr = downAlign(startAddr, PAGE_SIZE);
  VMA vma = VMA(prot, flags, size, hfmmap);
  // TODO: Check if offset should be contained in HostBackedFileMMap,
  // because hfmmaps are shared during unmaps.
  uint64_t retAddr = addVma(vma, startAddr);
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

  unmapPageTable_(addr, size);
  return value;
}

bool MemRegion::isVmMapped(uint64_t addr, size_t size) {
  for (auto itr = VMAlist_->begin(); itr != VMAlist_->end(); itr++) {
    if (itr->contains(addr, size) || itr->overlaps(addr, size)) {
      return true;
    }
  }
  return false;
}

VirtualMemoryArea MemRegion::getVMAFromAddr(uint64_t vaddr) {
  for (auto itr = VMAlist_->begin(); itr != VMAlist_->end(); itr++) {
    if (itr->contains(vaddr)) {
      return *itr;
    }
  }
  return VirtualMemoryArea{};
}

std::shared_ptr<std::list<VirtualMemoryArea>> MemRegion::getVmaList() {
  return VMAlist_;
}

bool MemRegion::overlapsHeap(uint64_t addr, size_t size) {
  return heapRegion_->overlaps(addr, size);
}

bool MemRegion::overlapsStack(uint64_t addr, size_t size) {
  return stackRegion_.overlaps(addr, size);
}

void MemRegion::printVmaList() {
  auto itr = VMAlist_->begin();
  std::cout << "Vma-list" << std::endl;
  uint16_t count = 1;
  while (itr != VMAlist_->end()) {
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
