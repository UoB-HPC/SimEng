#include "simeng/kernel/MemRegion.hh"

#include <iostream>
#include <vector>

namespace simeng {
namespace kernel {

MemRegion::MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t memSize,
                     uint64_t stackPtr, uint64_t heapStart, uint64_t pageSize,
                     uint64_t mmapStart)
    : stackSize_(stackSize),
      heapSize_(heapSize),
      memSize_(memSize),
      initStackStart_(stackPtr),
      startBrk_(heapStart),
      brk_(heapStart),
      pageSize_(pageSize),
      mmapStart_(mmapStart),
      maxHeapAddr_(calculateMaxHeapAddr()) {}

uint64_t MemRegion::calculateMaxHeapAddr() { return startBrk_ + heapSize_; }

uint64_t MemRegion::getStackSize() const { return stackSize_; }

uint16_t MemRegion::getHeapSize() const { return heapSize_; }

uint64_t MemRegion::getInitialStackStart() const { return initStackStart_; }

uint64_t MemRegion::getBrk() const { return brk_; }

uint64_t MemRegion::getBrkStart() const { return startBrk_; }

uint64_t MemRegion::getMmapStart() const { return mmapStart_; }

uint64_t MemRegion::getMemSize() const { return memSize_; }

uint64_t MemRegion::updateBrkRegion(uint64_t newBrk) {
  if (newBrk > maxHeapAddr_) {
    // This needs to fixed such that more extra memory allocation is mmapd.
    std::cerr
        << "Attemped to allocate more memory than is available to the process "
        << std::endl;
    std::exit(1);
  }
  if (newBrk > startBrk_) {
    brk_ = newBrk;
  }
  return brk_;
}

uint64_t MemRegion::addMmapVMA(VMA* vma) {
  // If linked list contains multiple VMAs then iterate
  // and check if new VMA can
  // be attached between two existing VMAs. If not append to the tail of the
  // linked list.
  if (vm_size_ > 1) {
    bool allocated = false;
    VMA* curr = vm_head_;
    while (curr->vm_next != nullptr) {
      if (curr->vm_next->vm_start - curr->vm_end >= vma->size) {
        vma->vm_start = curr->vm_end;
        vma->vm_next = curr->vm_next;
        curr->vm_next = vma;
        allocated = true;
        break;
      }
      curr = curr->vm_next;
    }
    // We are at the tail
    if (!allocated) {
      vma->vm_start = curr->vm_end;
      curr->vm_next = vma;
    }
    // If linked list only contains one VMA, then append to the tail.
  } else if (vm_size_ > 0) {
    vma->vm_start = vm_head_->vm_end;
    vm_head_->vm_next = vma;
  } else {
    vma->vm_start = mmapStart_;
    vm_head_ = vma;
  }
  // Round the end address to page size. This is needed for paging in virtual
  // memory. This mechanism will be more significant when proper implementation
  // of virtual memory is completed.
  vma->vm_end = roundUpMemAddr(vma->vm_start + vma->size, pageSize_);
  vm_size_++;
  // Return the assigned start address.
  return vma->vm_start;
}
int64_t MemRegion::removeMmapVMA(uint64_t addr, uint64_t length) {
  // Exit early if no entries
  if (vm_size_ == 0) {
    return 0;
  }
  size_t size = roundUpMemAddr(length, pageSize_);
  uint64_t startAddr = addr;
  uint64_t endAddr = addr + size;

  VMA* prev = nullptr;
  VMA* curr = vm_head_;
  std::vector<VMA*> removedVMAs;
  while (curr != nullptr) {
    // If addr matches the start address of VMA.
    if (curr->containedIn(addr, size)) {
      if (prev == nullptr) {
        vm_head_ = curr->vm_next;
      } else {
        prev->vm_next = curr->vm_next;
      }
      removedVMAs.push_back(curr);
      continue;
    }
    if (curr->contains(addr, size)) {
      VMA* newVma = new VMA(curr);
      curr->trimRangeStart(startAddr);
      newVma->trimRangeEnd(endAddr);
      newVma->vm_next = curr->vm_next;
      curr->vm_next = newVma;
      break;
    }
    if (curr->overlaps(addr, size)) {
      uint64_t endAddr = addr + size;
      // Check for overlaps
      if (addr > curr->vm_start && endAddr > curr->vm_end) {
        curr->trimRangeEnd(addr);
        continue;
      };
    }
    prev = curr;
    curr = curr->vm_next;
  }
  for (auto vma : removedVMAs) {
    delete vma;
  };
  // Not an error if the indicated range does no contain any mapped pages
  return 0;
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

uint64_t MemRegion::mmapRegion(uint64_t addr, uint64_t length, int prot,
                               int flags, HostFileMMap* hfmmap) {
  uint64_t startAddr = addr;
  // This is a tricky flag, if specified it means that we HAVE to use the hint
  // provided by the mmap syscall for VMA allocation. Sufficient care must be
  // taken during this call i.e we have to check whether the addr overlaps with
  // Heap or Stack VMA. If not, we still check whether the range overlaps with
  // any allocated VMAs if it does we need to unmap those regions first.
  uint64_t fixed = flags & MAP_FIXED;
  // Always use pageSize aligned sizes.
  uint64_t size = roundUpMemAddr(length, 4096);

  // No checks done currently to see if hint addresses lies in Mmap region. We
  // just allocate.
  if (startAddr) {
    if (overlapsHeapVM(startAddr, size) || overlapsStackVM(startAddr, size)) {
      std::cerr << "Provided hint overlaps with Stack and Heap region. This "
                   "shouldn't happen under normal circumstances."
                << std::endl;
      std::exit(1);
    };
  }

  if (fixed) {
    if (isVmMapped(startAddr, size)) {
      unmapRegion(addr, size, hfmmap->fd_, prot, flags);
    }
    VMA* vma = new VMA(hfmmap->fd_, hfmmap->offset_, prot, flags, size, Mmap);
    addMmapVMA(vma);
    return vma->vm_start;
  } else {
    // if not fixed and hint is provided then we need to check if the hint addr
    // is available. If not we allocate new address.
    if (!startAddr || isVmMapped(startAddr, size)) {
      mmapStart_ -= size;
      startAddr = mmapStart_;
    }
    // TODO: Check if offset should be contained in HostBackedFileMMap, because
    // hfmmaps are shared during unmaps.
    VMA* vma = new VMA(hfmmap->fd_, hfmmap->offset_, prot, flags, size, Mmap);
    addMmapVMA(vma);
    return vma->vm_start;
  }

  // O signifies an error.
  return 0;
}

int64_t MemRegion::unmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                               int flags) {
  uint64_t size = roundUpMemAddr(length, 4096);
  uint64_t value = removeMmapVMA(addr, size);

  // TODO: Unmap pageTable here.
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
}

bool MemRegion::overlapsHeapVM(uint64_t addr, size_t size) {
  return heap_vm_->overlaps(addr, size);
};

bool MemRegion::overlapsStackVM(uint64_t addr, size_t size) {
  return stack_vm_->overlaps(addr, size);
};

bool MemRegion::isPageAligned(uint64_t addr) {
  return addr & (pageSize_ - 1) == 0;
};

}  // namespace kernel
}  // namespace simeng
