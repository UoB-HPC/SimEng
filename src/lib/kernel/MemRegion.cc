#include "simeng/kernel/MemRegion.hh"

#include <iostream>

namespace simeng {
namespace kernel {

MemRegion::MemRegion(uint64_t stackSize, uint64_t heapSize, uint64_t memSize,
                     uint64_t stackStart, uint64_t startBrk, uint64_t pageSize,
                     uint64_t mmapStart)
    : stackSize_(stackSize),
      heapSize_(heapSize_),
      memSize_(memSize),
      initStackStart_(stackStart),
      startBrk_(startBrk),
      pageSize_(pageSize),
      mmapStart_(mmapStart),
      maxHeapAddr_(calculateMaxHeapAddr()) {}

uint64_t MemRegion::calculateMaxHeapAddr() { return startBrk_ + heapSize_; }
uint64_t MemRegion::getStackSize() const { return stackSize_; };
uint16_t MemRegion::getHeapSize() const { return heapSize_; };
uint64_t MemRegion::getInitialStackStart() const { return initStackStart_; };
uint64_t MemRegion::getBrk() const { return brk_; };
uint64_t MemRegion::getBrkStart() const { return startBrk_; };
uint64_t MemRegion::getMmapStart() const { return mmapStart_; };

uint64_t MemRegion::updateBrkRegion(uint64_t newBrk) {
  // Memory is being return back to the system.
  if (newBrk < brk_) {
    brk_ = newBrk;
    return brk_;
  }
  if (newBrk > maxHeapAddr_) {
    // This needs to fixed such that more extra memory allocation is mmapd.
    std::cerr
        << "Attemped to allocate more memory than is available to the process"
        << std::endl;
    std::exit(1);
  }
  brk_ = newBrk;
  return brk_;
};

uint64_t MemRegion::mmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                               int flags) {
  VirtMemArea* new_vma = (VirtMemArea*)malloc(sizeof(VirtMemArea));
  new_vma->length = length;
  return vma_ll.addVma(new_vma, mmapStart_, pageSize_);
};

void MemRegion::unmapRegion(uint64_t addr, uint64_t length, int fd, int prot,
                            int flags) {
  vma_ll.removeVma(addr, length, pageSize_);
  return;
}

void MemRegion::setInitialStackStart(uint64_t addr) { initStackStart_ = addr; }

uint64_t MemRegion::getMemSize() const { return memSize_; }
}  // namespace kernel
}  // namespace simeng