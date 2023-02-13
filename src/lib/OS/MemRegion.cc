#include "simeng/OS/MemRegion.hh"

#include <iostream>
#include <vector>

#include "simeng/kernel/Constants.hh"

namespace simeng {
namespace OS {

MemRegion::MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t mmapSize,
                     uint64_t memSize, uint64_t stackStart, uint64_t heapStart,
                     uint64_t mmapStart, uint64_t initStackPtr,
                     std::function<uint64_t(uint64_t, size_t)> unmapPageTable) {
  stackSize_ = stackSize;
  heapSize_ = heapSize;
  mmapSize_ = mmapSize;
  memSize_ = memSize;
  stackStart_ = stackStart;
  stackEnd_ = stackStart + stackSize;
  heapStart_ = heapStart;
  heapEnd_ = heapStart + heapSize;
  mmapStart_ = mmapStart;
  mmapEnd_ = mmapStart + mmapSize;
  initStackPtr_ = initStackPtr;
  brk_ = heapStart;
  mmapPtr_ = mmapStart;
  unmapPageTable_ = unmapPageTable;
}

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
  newBrk = upAlign(newBrk, 8);
  if (newBrk < heapStart_) {
    return brk_;
  }
  if (newBrk > heapEnd_) {
    // This needs to fixed such that more extra memory allocation is mmapd.
    std::cerr
        << "Attemped to allocate more memory than is available to the process "
        << std::endl;
    std::exit(1);
  }

  if (newBrk > brk_) {
    brk_ = newBrk;
  }
  return brk_;
}

uint64_t MemRegion::addVma(VMA* vma, uint64_t startAddr) {
  VMA* curr = vm_head_;
  size_t size = vma->vmSize_;
  // If start address is not 0, then look for a vma which has an end address
  // greater or equal to start address.
  if (startAddr && vm_size_ > 0) {
    while (curr->vmNext_ != nullptr) {
      if (curr->vmEnd_ >= startAddr) {
        break;
      }
      curr = curr->vmNext_;
    }
  }

  bool allocated = false;
  // If VmaList has multiple Vma then starting from curr (VMA) check if the
  // new VMA can be allocated between two existing ones.
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
  // If VMA has not been allocated it means that it couldn't fit between two
  // existing VMAs or VmaList is empty. This means that either we are the tail
  // of the VmaList or we are now allocating the head. If the startAddr is less
  // than mmap pointer its value will be set to the mmap pointer. However if it
  // is greater than the mmap pointer it remains the same. Here startAddr is
  // either mmap pointer or an address greater than mmap pointer.
  if (!allocated) {
    startAddr =
        ((startAddr > 0) && (startAddr >= mmapPtr_)) ? startAddr : mmapPtr_;
    vma->vmStart_ = startAddr;
    mmapPtr_ = startAddr + size;
    vma->vmEnd_ = mmapPtr_;
    if (vm_size_ == 0) {
      vm_head_ = vma;
    } else {
      curr->vmNext_ = vma;
    }
    vma->vmNext_ = nullptr;
  };
  vm_size_++;
  return vma->vmStart_;
}

int64_t MemRegion::removeVma(uint64_t addr, uint64_t length) {
  uint64_t endAddr = addr + length;

  VMA* prev = nullptr;
  VMA* curr = vm_head_;

  std::vector<VMA*> removedVMAs;
  uint64_t delsize = 0;

  while (curr != nullptr) {
    // If addr matches the start address of VMA.
    // if the address range completed contains the current VMA, delete the
    // entire VMA and decrease vma list size by 1.
    //  [--------Addr--------]
    //      [----VMA ----)
    if (curr->containedIn(addr, length)) {
      if (curr == vm_head_) {
        vm_head_ = curr->vmNext_;
      } else {
        prev->vmNext_ = curr->vmNext_;
      }
      vm_size_--;
      removedVMAs.push_back(curr);
    }
    // If the current VMA contains the address range split the VMA into two
    // smaller VMA, increase vma list size by 1.
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
        vm_size_++;
      }
      delsize += length;
      break;
    }
    // If the current VMA overlaps with the address range split, delete the
    // overlapping region and VMA list size remains same.
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
  };
  for (auto vma : removedVMAs) {
    delsize += vma->vmSize_;
    delete vma;
  };
  return delsize;
}

void MemRegion::removeVmaList() {
  if (vm_size_ == 0) return;
  VMA* curr = vm_head_;
  while (curr != nullptr) {
    VMA* temp = curr->vmNext_;
    delete curr;
    curr = temp;
  }
  vm_size_ = 0;
  vm_head_ = nullptr;
}

int64_t MemRegion::mmapRegion(uint64_t addr, uint64_t length, int prot,
                              int flags, HostFileMMap* hfmmap) {
  uint64_t startAddr = addr;

  // This is a tricky flag, if specified it means that we HAVE to use the
  // hint provided by the mmap syscall for VMA allocation. Sufficient care
  // must be taken during this call i.e we have to check whether the addr
  // overlaps with Heap or Stack VMA. If not, we still check whether the
  // range overlaps with any allocated VMAs if it does we need to unmap
  // those regions first.
  uint64_t fixed = flags & syscalls::mmap::flags::map_fixed;
  if (fixed) {
    std::cerr << "MAP_FIXED flag to MMAP calls is not supported yet."
              << std::endl;
    std::exit(1);
  }
  // Always use pageSize aligned sizes.
  uint64_t size = upAlign(length, page_size);

  // Check if provided hint address exists in VMA region or overlaps with heap
  // or stack regions.
  bool mapped = false;
  if (startAddr) {
    startAddr = upAlign(startAddr, page_size);
    if (overlapsHeap(startAddr, size) || overlapsStack(startAddr, size)) {
      std::cerr << "Provided hint overlaps with Stack and Heap region"
                << std::endl;
      return -EINVAL;
    };

    if (!((startAddr >= mmapStart_) && (startAddr + size < mmapEnd_))) {
      std::cout << "Provided address range doesn't exist in the mmap range: "
                << startAddr << " - " << startAddr + size << std::endl;
      return -EINVAL;
    };
    mapped = isVmMapped(startAddr, size);
  }

  // if not fixed and hint is provided then we need to check if the hint
  // address is available. If not we allocate vma at the most optimal address
  // available.
  VMA* vma = new VMA(prot, flags, size, hfmmap);
  if (startAddr && !mapped) {
    addVma(vma, startAddr);
  } else {
    // TODO: Check if offset should be contained in HostBackedFileMMap,
    // because hfmmaps are shared during unmaps.
    addVma(vma);
  }

  return vma->vmStart_;
}

int64_t MemRegion::unmapRegion(uint64_t addr, uint64_t length) {
  if (!((addr >= mmapStart_) && (addr + length < mmapEnd_))) {
    std::cout << "Provided address range doesn't exist in the mmap range: "
              << addr << " - " << addr + length << std::endl;
    return -1;
  };

  uint64_t size = upAlign(length, page_size);
  addr = downAlign(addr, page_size);
  uint64_t value = removeVma(addr, size);

  unmapPageTable_(addr, size);
  return value;
};

bool MemRegion::isVmMapped(uint64_t addr, size_t size) {
  VMA* curr = vm_head_;
  bool mapped = false;
  while (curr != NULL) {
    mapped =
        mapped || (curr->overlaps(addr, size) || curr->contains(addr, size));
    curr = curr->vmNext_;
  };
  return mapped;
};

VirtualMemoryArea* MemRegion::getVMAFromAddr(uint64_t vaddr) {
  VirtualMemoryArea* curr = vm_head_;
  while (curr != NULL) {
    if (curr->contains(vaddr)) {
      return curr;
    }
    curr = curr->vmNext_;
  };
  return NULL;
};

bool MemRegion::overlapsHeap(uint64_t addr, size_t size) {
  return (addr >= heapStart_) && (addr < heapEnd_) && (size != 0);
};

bool MemRegion::overlapsStack(uint64_t addr, size_t size) {
  return (addr >= stackStart_) && (addr < stackEnd_) && (size != 0);
};

}  // namespace OS
}  // namespace simeng
