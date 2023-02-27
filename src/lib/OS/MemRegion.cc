#include "simeng/OS/MemRegion.hh"

#include <iostream>
#include <memory>
#include <vector>

#include "simeng/OS/Constants.hh"

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
      vmall_(std::make_shared<VMALinkedList>()) {}

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

void MemRegion::updateStack(const uint64_t stackPtr) {
  VirtualMemoryArea* vma = getVMAFromAddr(stackPtr);
  // stackStart is vmEnd as stack grows down
  stackStart_ = vma->vmEnd_;
  stackEnd_ = vma->vmStart_;
  stackSize_ = vma->vmSize_;
  initStackPtr_ = stackPtr;
}

uint64_t MemRegion::addVma(VMA* vma, uint64_t startAddr) {
  VMA* curr = vmall_->vmHead;
  size_t size = vma->vmSize_;
  // When starAddr is not 0, search for an available address range
  // that can hold the new VMA with a starting address that is greater than or
  // equal to the specified startAddr. The following algorithm retrieves the
  // last existing VMA object before the address range so that the new VMA can
  // be linked between two existing VMAs. If no available address range is
  // found, then the new VMA is allocated at the end of the VMA list.
  if (startAddr && vmall_->vmSize > 0) {
    while (curr->vmNext_ != nullptr) {
      if (curr->vmEnd_ <= startAddr &&
          curr->vmNext_->vmStart_ >= (startAddr + size)) {
        break;
      }
      curr = curr->vmNext_;
    }
  }

  bool allocated = false;
  // If the VMA list has multiple VMAs then starting from curr (VMA) check if
  // the new VMA can be allocated between two existing ones.
  while (curr != nullptr && curr->vmNext_ != nullptr) {
    if (curr->vmNext_->vmStart_ - curr->vmEnd_ >= size) {
      vma->vmStart_ = curr->vmEnd_;
      vma->vmNext_ = curr->vmNext_;
      vma->vmEnd_ = curr->vmEnd_ + size;
      curr->vmNext_ = vma;
      allocated = true;
      break;
    }
    curr = curr->vmNext_;
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
    vma->vmStart_ = startAddr;
    mmapPtr_ = startAddr + size;
    vma->vmEnd_ = mmapPtr_;
    if (vmall_->vmSize == 0) {
      vmall_->vmHead = vma;
    } else {
      curr->vmNext_ = vma;
    }
    vma->vmNext_ = nullptr;
  }
  vmall_->vmSize++;
  return vma->vmStart_;
}

int64_t MemRegion::removeVma(uint64_t addr, uint64_t length) {
  uint64_t endAddr = addr + length;

  VMA* prev = nullptr;
  VMA* curr = vmall_->vmHead;

  std::vector<VMA*> removedVMAs;
  uint64_t delsize = 0;

  while (curr != nullptr) {
    // If the address range completely contains the current VMA, delete the
    // entire VMA and decrease VMA list size by 1.
    //  [--------Addr--------]
    //      [----VMA ----)
    if (curr->containedIn(addr, length)) {
      if (curr == vmall_->vmHead) {
        vmall_->vmHead = curr->vmNext_;
      } else {
        prev->vmNext_ = curr->vmNext_;
      }
      vmall_->vmSize--;
      removedVMAs.push_back(curr);
    }
    // If the address range is within the bounds of the current VMA, split the
    // VMA into two smaller VMAs and increase the VMA list size by 1
    //      [---Addr---]
    // [--------VMA --------)
    else if (curr->contains(addr, length)) {
      if (addr == curr->vmStart_) {
        curr->trimRangeStart(endAddr);
      } else if (endAddr == curr->vmEnd_) {
        curr->trimRangeEnd(addr);
      } else {
        VMA* newVma = new VMA(curr);
        curr->trimRangeEnd(addr);
        newVma->trimRangeStart(endAddr);
        newVma->vmNext_ = curr->vmNext_;
        curr->vmNext_ = newVma;
        vmall_->vmSize++;
      }
      delsize += length;
      break;
    }
    // If the current VMA overlaps with the address range delete the
    // overlapping region of the VMA.
    //          [--------Addr--------]
    //  [--------VMA --------)
    else if (curr->overlaps(addr, length)) {
      if (addr > curr->vmStart_ && endAddr > curr->vmEnd_) {
        delsize += (curr->vmEnd_ - addr);
        curr->trimRangeEnd(addr);
        prev = curr;
      } else {
        delsize += (endAddr - curr->vmStart_);
        curr->trimRangeStart(endAddr);
        break;
      }
    } else {
      prev = curr;
    }
    curr = curr->vmNext_;
  }
  for (auto vma : removedVMAs) {
    delsize += vma->vmSize_;
    delete vma;
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
  VMA* vma = new VMA(prot, flags, size, hfmmap);
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
  VMA* curr = vmall_->vmHead;
  bool mapped = false;
  while (curr != NULL) {
    mapped =
        mapped || (curr->overlaps(addr, size) || curr->contains(addr, size));
    curr = curr->vmNext_;
  }
  return mapped;
}

VirtualMemoryArea* MemRegion::getVMAFromAddr(uint64_t vaddr) {
  VirtualMemoryArea* curr = vmall_->vmHead;
  while (curr != NULL) {
    if (curr->contains(vaddr)) {
      return curr;
    }
    curr = curr->vmNext_;
  }
  return NULL;
}

bool MemRegion::overlapsHeap(uint64_t addr, size_t size) {
  return (addr >= heapStart_) && (addr < heapEnd_) && (size != 0);
}

bool MemRegion::overlapsStack(uint64_t addr, size_t size) {
  return (addr >= stackStart_) && (addr < stackEnd_) && (size != 0);
}

}  // namespace OS
}  // namespace simeng
