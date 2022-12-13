#pragma once

#include <stdint.h>

#include <cstddef>
#include <memory>
namespace simeng {
namespace kernel {

/** struct representing vm_area_struct in linux. */
struct VirtMemArea {
  /** The address representing the end of the memory allocation. */
  uint64_t vm_end = 0;
  /** The address representing the start of the memory allocation. */
  uint64_t vm_start = 0;
  /** The next allocation in the contiguous list. */
  VirtMemArea* vm_next = nullptr;
  uint64_t length = 0;
};

/** Class representing VMA linked list*/
class Vmall {
 private:
  VirtMemArea* vm_head_ = nullptr;
  VirtMemArea* vm_tail_ = nullptr;
  size_t vm_size_ = 0;

 public:
  ~Vmall() {}
  uint64_t addVma(VirtMemArea* vma, uint64_t mmapStart, uint64_t pageSize);
  void removeVma(uint64_t addr, uint64_t length, uint64_t pageSize);
  size_t getSize();
  void freeVma();
};

}  // namespace kernel
}  // namespace simeng