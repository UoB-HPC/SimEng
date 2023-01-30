#include "simeng/kernel/MemRegion.hh"

#include <iostream>
#include <vector>

namespace simeng {
namespace kernel {

MemRegion::MemRegion(size_t stackSize, size_t heapSize, size_t mmapSize,
                     size_t memSize, uint64_t pageSize, uint64_t stackStart,
                     uint64_t heapStart, uint64_t mmapStart,
                     uint64_t initStackPtr,
                     std::function<uint64_t(uint64_t, size_t)> unmapPageTable) {
  stackSize_ = stackSize;
  heapSize_ = heapSize;
  mmapSize_ = mmapSize;
  memSize_ = memSize;
  pageSize_ = pageSize;
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
  if (newBrk < heapStart_) {
    return brk_;
  }
  newBrk = roundUpMemAddr(newBrk, pageSize_);

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

uint64_t MemRegion::addVma(VMA* vma) {
  // If linked list contains multiple VMAs then iterate
  // and check if new VMA can
  // be attached between two existing VMAs. If not append to the tail of the
  // linked list.
  size_t size = vma->size;
  if (vm_size_ > 0) {
    bool allocated = false;
    VMA* curr = vm_head_;
    while (curr->vm_next != nullptr) {
      if (curr->vm_next->vm_start - curr->vm_end >= size) {
        vma->vm_start = curr->vm_end;
        vma->vm_next = curr->vm_next;
        vma->vm_end = curr->vm_end + size;
        curr->vm_next = vma;
        allocated = true;
        break;
      }
      curr = curr->vm_next;
    }
    // We are at the tail
    if (!allocated) {
      vma->vm_start = mmapPtr_;
      mmapPtr_ += size;
      vma->vm_end = mmapPtr_;
      curr->vm_next = vma;
    }
    // If linked list only contains one VMA, then append to the tail.
  } else {
    vma->vm_start = mmapPtr_;
    mmapPtr_ += size;
    vma->vm_end = mmapPtr_;
    vm_head_ = vma;
    vma->vm_next = nullptr;
  }
  vm_size_++;
  // Return the assigned start address.
  return vma->vm_start;
}

uint64_t MemRegion::addVma(VMA* vma, uint64_t startAddr) {
  // If linked list contains multiple VMAs then iterate
  // and check if new VMA can
  // be attached between two existing VMAs. If not append to the tail of the
  // linked list.
  uint64_t endAddr = startAddr + vma->size;
  if (vm_size_ > 0) {
    bool allocated = false;
    VMA* curr = vm_head_;
    while (curr->vm_next != nullptr) {
      if (endAddr <= curr->vm_next->vm_start && curr->vm_end >= startAddr) {
        vma->vm_start = startAddr;
        vma->vm_next = curr->vm_next;
        curr->vm_next = vma;
        allocated = true;
        break;
      }
      curr = curr->vm_next;
    }
    // We are at the tail
    if (!allocated) {
      vma->vm_start = startAddr;
      curr->vm_next = vma;
      mmapPtr_ = endAddr;
    }
    // If linked list only contains one VMA, then append to the tail.
  } else {
    vma->vm_start = startAddr;
    vm_head_ = vma;
  }
  vma->vm_end = endAddr;
  vm_size_++;
  // Return the assigned start address.
  return vma->vm_start;
}

int64_t MemRegion::removeVma(uint64_t addr, uint64_t length) {
  uint64_t endAddr = addr + length;

  VMA* prev = nullptr;
  VMA* curr = vm_head_;

  std::vector<VMA*> removedVMAs;
  uint64_t delsize = 0;

  while (curr != nullptr) {
    // If addr matches the start address of VMA.
    if (curr->containedIn(addr, length)) {
      if (curr == vm_head_) {
        vm_head_ = curr->vm_next;
      } else {
        prev->vm_next = curr->vm_next;
      }
      vm_size_--;
      removedVMAs.push_back(curr);
    } else if (curr->contains(addr, length)) {
      if (addr == curr->vm_start) {
        curr->trimRangeStart(endAddr);
      } else if (endAddr == curr->vm_end) {
        curr->trimRangeEnd(addr);
      } else {
        VMA* newVma = new VMA(curr);
        curr->trimRangeEnd(addr);
        newVma->trimRangeStart(endAddr);
        newVma->vm_next = curr->vm_next;
        curr->vm_next = newVma;
        vm_size_++;
      }
      delsize += length;
      break;
    } else if (curr->overlaps(addr, length)) {
      if (addr > curr->vm_start && endAddr > curr->vm_end) {
        delsize += (curr->vm_end - addr);
        curr->trimRangeEnd(addr);
        prev = curr;
      } else {
        delsize += (endAddr - curr->vm_start);
        curr->trimRangeStart(endAddr);
        break;
      }
    } else {
      prev = curr;
    }
    curr = curr->vm_next;
  };
  for (auto vma : removedVMAs) {
    delsize += vma->size;
    delete vma;
  };
  return delsize;
}

void MemRegion::freeVma() {
  if (vm_size_ == 0) return;
  VMA* curr = vm_head_;
  while (curr != nullptr) {
    VMA* temp = curr->vm_next;
    delete curr;
    curr = temp;
  }
  vm_size_ = 0;
  vm_head_ = nullptr;
}

int64_t MemRegion::mmapRegion(uint64_t addr, uint64_t length, int prot,
                              int flags, HostFileMMap* hfmmap) {
  uint64_t startAddr = addr;

  uint64_t foffset = 0;
  int fd = -1;
  if (hfmmap != nullptr) {
    foffset = hfmmap->offset_;
    fd = hfmmap->fd_;
  }

  // This is a tricky flag, if specified it means that we HAVE to use the
  // hint provided by the mmap syscall for VMA allocation. Sufficient care
  // must be taken during this call i.e we have to check whether the addr
  // overlaps with Heap or Stack VMA. If not, we still check whether the
  // range overlaps with any allocated VMAs if it does we need to unmap
  // those regions first.
  uint64_t fixed = flags & MAP_FIXED;
  // Always use pageSize aligned sizes.
  uint64_t size = roundUpMemAddr(length, 4096);

  // No checks done currently to see if hint addresses lies in Mmap region.
  // We just allocate.
  if (startAddr) {
    startAddr = roundUpMemAddr(startAddr, 4096);
    std::cout << startAddr << std::endl;
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
  }
  bool mapped = isVmMapped(startAddr, size);
  if (fixed) {
    if (mapped) unmapRegion(addr, size);

    VMA* vma = new VMA(prot, flags, size, Mmap, hfmmap);
    addVma(vma);
    return vma->vm_start;
  } else {
    // if not fixed and hint is provided then we need to check if the hint
    // addr is available. If not we allocate new address.
    VMA* vma = new VMA(prot, flags, size, Mmap, hfmmap);
    if (startAddr && !mapped) {
      addVma(vma, startAddr);
    } else {
      // TODO: Check if offset should be contained in HostBackedFileMMap,
      // because hfmmaps are shared during unmaps.
      addVma(vma);
    }
    return vma->vm_start;
  }

  // O signifies an error.
  return 0;
}

int64_t MemRegion::unmapRegion(uint64_t addr, uint64_t length) {
  uint64_t size = roundUpMemAddr(length, 4096);
  addr = roundDownMemAddr(addr, 4096);
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
    curr = curr->vm_next;
  };
  return mapped;
};

void MemRegion::addInitalVMA(char* data, uint64_t startAddr, size_t size,
                             VMAType type) {
  /*
// discard char* data for now until we make page trnaslation.
if (type == Mmap) {
  std::cerr << "Mmap VMAs should not be added using the addInitialVMA "
               "method. Use the mmap syscall instead."
            << std::endl;
  return;
};

size = roundUpMemAddr(size, pageSize_);
startAddr = roundDownMemAddr(startAddr, pageSize_);
uint64_t endAddr = startAddr + size;

VMA* vma = new VMA(-1, 0, 0, 0, size, type);
vma->vm_start = startAddr;
vma->vm_end = endAddr;

if (type == PTLoad) {
  if (ptload_vm_ == NULL) {
    ptload_vm_ = vma;
    return;
  }
  VMA* curr = ptload_vm_;
  while (curr->vm_next != NULL) {
    curr = curr->vm_next;
  }
  curr->vm_next = vma;
} else if (type == Stack) {
  stack_vm_ = vma;
} else {
  heap_vm_ = vma;
}
*/
}

VirtualMemoryArea* MemRegion::getVMAFromAddr(uint64_t vaddr) {
  VirtualMemoryArea* curr = vm_head_;
  while (curr != NULL) {
    //  std::cout << "Curr start: " << curr->vm_start << std::endl;
    // std::cout << "Curr end: " << curr->vm_end << std::endl;
    // std::cout << " ------------------------- " << std::endl;
    if (curr->contains(vaddr)) {
      return curr;
    }
    curr = curr->vm_next;
  };
  return NULL;
};

bool MemRegion::overlapsHeap(uint64_t addr, size_t size) {
  uint64_t endAddr = addr + size;
  return (addr >= heapStart_) && (addr < heapEnd_) && (size != 0);
};

bool MemRegion::overlapsStack(uint64_t addr, size_t size) {
  uint64_t endAddr = addr + size;
  return (addr >= stackStart_) && (addr < stackEnd_) && (size != 0);
};

bool MemRegion::isPageAligned(uint64_t addr) {
  return addr & (pageSize_ - 1) == 0;
};

}  // namespace kernel
}  // namespace simeng
