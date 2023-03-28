#include "simeng/OS/MemRegion.hh"

#include <cstdint>
#include <iostream>
#include <iterator>
#include <memory>
#include <vector>

#include "simeng/OS/Constants.hh"
#include "simeng/OS/Vma.hh"

namespace simeng {
namespace OS {

MemRegion::MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t mmapSize,
                     uint64_t procImgSize, uint64_t stackStart,
                     uint64_t heapStart, uint64_t mmapStart,
                     uint64_t initStackPtr,
                     std::function<uint64_t(uint64_t, size_t)> unmapPageTable)

    : stackRegion_(ProcessStackRegion(stackStart, stackSize, initStackPtr)),
      heapRegion_(std::make_shared<ProcessHeapRegion>(heapStart, heapSize)),
      mmapRegion_(std::make_shared<ProcessMmapRegion>(mmapStart, mmapSize)),
      procImgSize_(procImgSize),
      unmapPageTable_(unmapPageTable),
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

uint64_t MemRegion::updateBrkRegion(uint64_t newBrk) {
  if (newBrk == 0 || newBrk == heapRegion_->brk) {
    return heapRegion_->brk;
  }
  // We have to make sure that the binary under simulation isn't trying to
  // deallocate more memory than is present in the process heap region.
  if (newBrk < heapRegion_->start) {
    std::cerr << "[SimEng:MemRegion] Attemped to deallocate more memory than "
                 "is available to the process heap region."
              << std::endl;
    std::exit(1);
  }
  // For simplicity we update only the brk point when the binary under
  // simulation is giving memory back to the system. We do not delete any page
  // table mappings or page frames assosciated with the deallocated memory
  // region.
  if (newBrk < heapRegion_->brk) {
    heapRegion_->brk = newBrk;
    return heapRegion_->brk;
  }
  if (newBrk > heapRegion_->end) {
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

  if (newBrk > heapRegion_->brk) {
    heapRegion_->brk = newBrk;
  }
  return heapRegion_->brk;
}

void MemRegion::updateStack(const uint64_t stackPtr) {
  VirtualMemoryArea vma = getVMAFromAddr(stackPtr);
  // stackStart is vmEnd as stack grows down.
  stackRegion_ = ProcessStackRegion(vma.vmEnd_, vma.vmSize_, stackPtr);
}

uint64_t MemRegion::addVma(VMA vma, uint64_t startAddr) {
  bool isStartAddrValid =
      (startAddr >= mmapStart_) && (startAddr + vma.vmSize_ < mmapEnd_);
  if (startAddr != 0 && !isStartAddrValid) {
    std::cout << "[SimEng:MemRegion] Provided address range doesn't exist in "
                 "the mmap range: "
              << startAddr << " - " << startAddr + vma.vmSize_ << std::endl;
    return -1;
  }
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
    // As per the mmap specification, if the VMA list has multiple VMAs then
    // starting from the beginning of the VMA list check if the new VMA can be
    // allocated between two existing ones. If startAddr is 0 check all address
    // ranges between existing VMAs. However, if startAddr is non-zero then only
    // search for an available address range which either contains startAddr or
    // has a starting address greater than startAddr. If no address range is
    // found, then the new VMA is allocated at the end of VMA list.
    while (itr != last) {
      auto next = std::next(itr, 1);
      bool rangeSucceedsOrContainsSAddr = next->vmStart_ > startAddr;
      uint64_t vmaStart = itr->vmEnd_ <= startAddr ? startAddr : itr->vmEnd_;
      uint64_t rangeSpace = next->vmStart_ - vmaStart;
      if (rangeSucceedsOrContainsSAddr && rangeSpace >= size) {
        vma.vmStart_ = vmaStart;
        vma.vmEnd_ = vmaStart + size;
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

  VMA vma = VMA(prot, flags, size, hfmmap);
  // Check if provided hint address exists in VMA region or overlaps with heap
  // or stack regions.
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
  }
  // TODO: Check if offset should be contained in HostBackedFileMMap,
  // because hfmmaps are shared during unmaps.
  return addVma(vma, startAddr);
}

int64_t MemRegion::unmapRegion(uint64_t addr, uint64_t length) {
  if (!((addr >= mmapRegion_->start) && (addr + length < mmapRegion_->end))) {
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
  return heapRegion_->overlaps(addr, size);
}

bool MemRegion::overlapsStack(uint64_t addr, size_t size) {
  return stackRegion_.overlaps(addr, size);
}

}  // namespace OS
}  // namespace simeng
