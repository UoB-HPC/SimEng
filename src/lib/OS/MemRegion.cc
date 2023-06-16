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

#define AS_STRING(x) #x

#define PRINT_MMAP_FLAGS(flags, flag_val)          \
  if (flags & flag_val) {                          \
    std::cout << AS_STRING(flag_val) << std::endl; \
  }

namespace simeng {
namespace OS {

using namespace syscalls::mmap::flags;

MemRegion::MemRegion(
    uint64_t stackStart, uint64_t stackEnd, uint64_t heapStart,
    uint64_t heapEnd, uint64_t mmapStart, uint64_t mmapEnd,
    uint64_t initStackPtr,
    std::function<uint64_t(uint64_t, size_t)> unmapPageTable)
    : stackRegion_(ProcessStackRegion(stackStart, stackEnd, initStackPtr)),
      heapRegion_(std::make_shared<ProcessHeapRegion>(heapStart, heapEnd)),
      mmapRegion_(std::make_shared<ProcessMmapRegion>(mmapStart, mmapEnd)),
      procImgSize_(stackStart),
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

uint64_t MemRegion::updateBrkRegion(uint64_t brk) {
  // We have to make sure that the binary under simulation isn't trying to
  // deallocate more memory than is present in the process heap region.
  if (brk < heapRegion_->startBrk) {
    std::cerr << "[SimEng:MemRegion] Attemped to deallocate more memory than "
                 "is available to the process heap region."
              << std::endl;
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
  assert(
      retAddr == newBrk &&
      "[SimEng:MemRegion] Address returned by mmapRegion with MAP_FIXED flag"
      "returned different address - updateBrk.");
  heapRegion_->brk = brk;

  return brk;
}

void MemRegion::updateStack(const uint64_t stackPtr) {
  VirtualMemoryArea vma = getVMAFromAddr(stackPtr);
  // stackStart is vmEnd as stack grows down.
  stackRegion_ = ProcessStackRegion(vma.vmEnd_, vma.vmSize_, stackPtr);
}

uint64_t MemRegion::addVma(VMA vma, uint64_t startAddr) {
  bool isStartAddrValid = (startAddr >= mmapRegion_->start) &&
                          (startAddr + vma.vmSize_ < mmapRegion_->end);
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
    // Check if the new VMA can be allocated between mmapStart and the first
    // VMA in the VMA list.
    uint64_t effectiveMmapStart = startAddr ? startAddr : mmapRegion_->start;
    uint64_t space = itr->vmStart_ - effectiveMmapStart;
    if (effectiveMmapStart < itr->vmStart_ && space >= size) {
      vma.vmStart_ = effectiveMmapStart;
      vma.vmEnd_ = effectiveMmapStart + size;
      VMAlist_->insert(itr, vma);
      return vma.vmStart_;
    }
    // As per the mmap specification, if the VMA list has multiple VMAs then
    // starting from the beginning of the VMA list check if the new VMA can
    // be allocated between two existing ones. If startAddr is 0 check all
    // address ranges between existing VMAs. However, if startAddr is
    // non-zero then only search for an available address range which either
    // contains startAddr or has a starting address greater than startAddr.
    // If no address range is found, then the new VMA is allocated at the
    // end of VMA list.
    while (itr != last) {
      auto next = std::next(itr, 1);
      bool rangeSucceedsOrContainsSAddr = next->vmStart_ > startAddr;
      uint64_t vmaStart = itr->vmEnd_ <= startAddr ? startAddr : itr->vmEnd_;
      uint64_t rangeSpace = next->vmStart_ - vmaStart;
      if (rangeSucceedsOrContainsSAddr && rangeSpace >= size) {
        vma.vmStart_ = vmaStart;
        vma.vmEnd_ = vmaStart + size;
        // std::list::insert inserts elements before the position specified
        // by the iterator, hence why next is used instead of itr.
        VMAlist_->insert(next, vma);
        allocated = true;
        break;
      }
      itr++;
    }
  }
  // If the new VMA has not been allocated it means that it couldn't fit
  // between two existing VMAs or the VMA list is empty. This means that
  // either we are the tail of the VMA list or we are now allocating the
  // head. If the startAddr is less than mmap pointer its value will be set
  // to the mmap pointer. However if it is greater than the mmap pointer it
  // remains the same. Here startAddr is either mmap pointer or an address
  // greater than mmap pointer.
  if (!allocated) {
    startAddr =
        startAddr >= mmapRegion_->mmapPtr ? startAddr : mmapRegion_->mmapPtr;
    vma.vmStart_ = startAddr;
    mmapRegion_->mmapPtr = startAddr + size;
    vma.vmEnd_ = mmapRegion_->mmapPtr;
    VMAlist_->push_back(vma);
  }
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

int64_t MemRegion::mmapRegion(
    uint64_t startAddr, uint64_t length, int prot, int flags,
    HostFileMMap hfmmap) {
  // Check if flag contains MAP_FIXED, as it is not supported yet.
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_FIXED);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_SYNC);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_STACK);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_LOCKED);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_SHARED);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_HUGETLB);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_PRIVATE);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_NONBLOCK);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_POPULATE);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_ANONYMOUS);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_DENYWRITE);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_GROWSDOWN);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_NORESERVE);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_EXECUTABLE);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_UNINITIALIZED);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_FIXED_NOREPLACE);
  PRINT_MMAP_FLAGS(flags, SIMENG_MAP_SHARED_VALIDATE);

  if (startAddr + length > stackRegion_.end) {
    std::cerr << "[SimEng:MemRegion] Address range given to mmapRegion is "
                 "greater than virtual address space"
              << std::endl;
    return -1;
  }

  // mmap_min_addr
  if (startAddr < PAGE_SIZE) {
    std::cerr << "[SimEng::MemRegion] Start address given to mmapRegion is "
                 "less than mmap_min_addr."
              << std::endl;
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
    if (isVmMapped(startAddr, size)) {
      // unmap
    }
    VMA vma = VMA(prot, flags, size, hfmmap);
    return addVmaExactlyAtAddr(vma, startAddr);
  }

  startAddr = downAlign(startAddr, PAGE_SIZE);
  VMA vma = VMA(prot, flags, size, hfmmap);
  // TODO: Check if offset should be contained in HostBackedFileMMap,
  // because hfmmaps are shared during unmaps.
  return addVma(vma, startAddr);
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
