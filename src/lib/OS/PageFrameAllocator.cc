#include "simeng/OS/PageFrameAllocator.hh"

#include <iostream>

#include "simeng/util/Math.hh"
namespace simeng {
namespace OS {

PageFrameAllocator::PageFrameAllocator(uint64_t maxSize, uint64_t pageSize)
    : pageSize_(pageSize), maxAllocationSize_(maxSize) {
  sizeLeft_ = maxSize;
};

PageFrameAllocator::~PageFrameAllocator(){};

uint64_t PageFrameAllocator::allocate(size_t size) {
  size = roundUpMemAddr(size, pageSize_);
  if (size > sizeLeft_) {
    std::cerr << "Cannot allocate more page frames! Increase system memory."
              << std::endl;
    std::exit(1);
  }
  uint64_t paddr = nextFreeAddr_;
  sizeLeft_ -= size;
  nextFreeAddr_ += size;
  return paddr;
};

}  // namespace OS
}  // namespace simeng
