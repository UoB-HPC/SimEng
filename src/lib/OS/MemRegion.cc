#include "simeng/OS/MemRegion.hh"

#include <iostream>
#include <iterator>
#include <memory>
#include <vector>

#include "simeng/OS/Constants.hh"
#include "simeng/OS/Vma.hh"

namespace simeng {
namespace OS {

MemRegion::MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t mmapSize,
                     uint64_t memSize, uint64_t stackStart, uint64_t heapStart,
                     uint64_t mmapStart, uint64_t initStackPtr,
                     std::function<uint64_t(uint64_t, size_t)> unmapPageTable)
    : stackStart_(stackStart),
      stackEnd_(stackStart + stackSize),
      stackSize_(stackSize),
      initStackPtr_(initStackPtr),
      heapStart_(heapStart),
      heapEnd_(heapStart + heapSize),
      heapSize_(heapSize),
      brk_(heapStart),
      memSize_(memSize),
      mmapStart_(mmapStart),
      mmapEnd_(mmapStart + mmapSize),
      mmapPtr_(mmapStart),
      mmapSize_(mmapSize),
      unmapPageTable_(unmapPageTable),
      VMAlist_(std::make_shared<std::list<VirtualMemoryArea>>()) {}

MemRegion::~MemRegion() {}

uint64_t MemRegion::getStackStart() const { return stackStart_; }

uint64_t MemRegion::getStackEnd() const { return stackEnd_; }

size_t MemRegion::getStackSize() const { return stackSize_; }

uint64_t MemRegion::getInitialStackPtr() const { return initStackPtr_; }

uint64_t MemRegion::getHeapStart() const { return heapStart_; }

uint64_t MemRegion::getHeapEnd() const { return heapEnd_; }

size_t MemRegion::getHeapSize() const { return heapSize_; }

uint64_t MemRegion::getBrk() const { return brk_; }

uint64_t MemRegion::getMmapStart() const { return mmapStart_; }

uint64_t MemRegion::getMemSize() const { return memSize_; }

uint64_t MemRegion::updateBrkRegion(uint64_t newBrk) {
  if (newBrk < heapStart_) {
    return brk_;
  }
  if (newBrk > heapEnd_) {
    // TODO: This needs to fixed such that more extra memory allocation is
    // mmapd.
    std::cerr
        << "[SimEng:MemRegion] Attemped to allocate more memory on the "
           "heap than is available to the process. Please increase the "
           "{Process-Image:{Heap-Size: <size>}} parameter in the YAML model "
           "config file used to run this simulation."
        << std::endl;
    std::exit(1);
  }

  if (newBrk > brk_) {
    brk_ = newBrk;
  }
  return brk_;
}

uint64_t MemRegion::addVma(VMA vma, uint64_t startAddr) {
  size_t size = vma.vmSize_;
  auto last = std::prev(VMAlist_->end(), 1);
  bool allocated = false;

  auto itr = VMAlist_->begin();
  if (VMAlist_->size() > 0) {
    // Check if the new VMA can be allocated between mmapStart and the first VMA
    // in the VMA list.
    uint64_t effectiveMmapStart = startAddr ? startAddr : mmapStart_;
    uint64_t space = itr->vmStart_ - effectiveMmapStart;
    if (effectiveMmapStart < itr->vmStart_ && space >= size) {
      vma.vmStart_ = effectiveMmapStart;
      vma.vmEnd_ = effectiveMmapStart + size;
      VMAlist_->insert(itr, vma);
      return vma.vmStart_;
    }
    // If the VMA list has multiple VMAs then starting from the beginning of the
    // VMA list check if the new VMA can be allocated between two existing ones.
    // If startAddr is 0 check all address ranges between existing VMAs.
    // However, if startAddr is non-zero then only search for an available
    // address range with a starting address greater than startAddr. If no
    // address range is found, then the new VMA is allocated at the end of VMA
    // list.
    while (itr != last) {
      auto next = std::next(itr, 1);
      bool currRangeSuceedsStartAddr = true;
      uint64_t rangeSpace = next->vmStart_ - itr->vmEnd_;
      if (startAddr) {
        currRangeSuceedsStartAddr =
            next->vmStart_ > startAddr && itr->vmEnd_ <= startAddr;
        rangeSpace = next->vmStart_ - startAddr;
      }
      if (currRangeSuceedsStartAddr && rangeSpace >= size) {
        vma.vmStart_ = itr->vmEnd_;
        vma.vmEnd_ = itr->vmEnd_ + size;
        // std::list::insert inserts elements before the position specified by
        // the iterator, hence why next is used instead of itr.
        VMAlist_->insert(next, vma);
        allocated = true;
        break;
      }
      itr++;
    }
  }
  // If the new VMA has not been allocated it means that it couldn't fit between
  // two existing VMAs or the VMA list is empty. This means that either we are
  // the tail of the VMA list or we are now allocating the head. If the
  // startAddr is less than mmap pointer its value will be set to the mmap
  // pointer. However if it is greater than the mmap pointer it remains the
  // same. Here startAddr is either mmap pointer or an address greater than mmap
  // pointer.
  if (!allocated) {
    startAddr = startAddr >= mmapPtr_ ? startAddr : mmapPtr_;
    vma.vmStart_ = startAddr;
    mmapPtr_ = startAddr + size;
    vma.vmEnd_ = mmapPtr_;
    VMAlist_->push_back(vma);
  }
  return vma.vmStart_;
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
    // If the address range is within the bounds of the current VMA, split the
    // VMA into two smaller VMAs and increase the VMA list size by 1
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
        // std::list::insert inserts element before the position specified by
        // the iterator. Hence std::next is used to advance the iterator so that
        // the new VMA can be inserted at the correct place.
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
  // Check if flag contains MAP_FIXED, as it is not supported yet.
  uint64_t fixed = flags & syscalls::mmap::flags::SIMENG_MAP_FIXED;
  if (fixed) {
    std::cerr << "[SimEng:MemRegion] MAP_FIXED flag to MMAP calls is not "
                 "supported yet."
              << std::endl;
    std::exit(1);
  }
  // Always use pageSize aligned sizes.
  uint64_t size = upAlign(length, PAGE_SIZE);

  // Check if provided hint address exists in VMA region or overlaps with heap
  // or stack regions.
  bool mapped = false;
  if (startAddr) {
    startAddr = upAlign(startAddr, PAGE_SIZE);
    if (overlapsStack(startAddr, size)) {
      std::cerr
          << "[SimEng:MemRegion] Provided hint overlaps with the Stack region"
          << std::endl;
      return -1;
    }
    if (overlapsHeap(startAddr, size)) {
      std::cerr
          << "[SimEng:MemRegion] Provided hint overlaps with the Heap region"
          << std::endl;
      return -1;
    }

    if (!((startAddr >= mmapStart_) && (startAddr + size < mmapEnd_))) {
      std::cout << "[SimEng:MemRegion] Provided address range doesn't exist in "
                   "the mmap range: "
                << startAddr << " - " << startAddr + size << std::endl;
      return -1;
    }
    mapped = isVmMapped(startAddr, size);
  }

  // if not fixed and hint is provided then we need to check if the hint
  // address is available. If not we allocate vma at the most optimal address
  // available.
  VMA vma = VMA(prot, flags, size, hfmmap);
  uint64_t returnAddress = 0;
  if (startAddr && !mapped) {
    returnAddress = addVma(vma, startAddr);
  } else {
    // TODO: Check if offset should be contained in HostBackedFileMMap,
    // because hfmmaps are shared during unmaps.
    returnAddress = addVma(vma);
  }

  return returnAddress;
}

int64_t MemRegion::unmapRegion(uint64_t addr, uint64_t length) {
  if (!((addr >= mmapStart_) && (addr + length < mmapEnd_))) {
    std::cout << "[SimEng:MemRegion] Provided address range doesn't exist in "
                 "the mmap range: "
              << addr << " - " << addr + length << std::endl;
    return -1;
  }

  uint64_t size = upAlign(length, PAGE_SIZE);
  addr = downAlign(addr, PAGE_SIZE);
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
  return (addr >= heapStart_) && (addr < heapEnd_) && (size != 0);
}

bool MemRegion::overlapsStack(uint64_t addr, size_t size) {
  return (addr >= stackStart_) && (addr < stackEnd_) && (size != 0);
}

}  // namespace OS
}  // namespace simeng
