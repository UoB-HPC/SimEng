#pragma once

#include <stdint.h>

#include <cstddef>
#include <iostream>
#include <memory>

#include "simeng/util/Math.hh"
namespace simeng {
namespace kernel {

/** struct representing vm_area_struct in linux. (Linked List) */
struct VirtMemArea {
  /** The address representing the end of the memory allocation. */
  uint64_t vm_end = 0;
  /** The address representing the start of the memory allocation. */
  uint64_t vm_start = 0;
  /** The next allocation in the contiguous list. */
  VirtMemArea* vm_next = nullptr;
  /** The size of the virtual memory area. */
  uint64_t length = 0;
};

// class VirtualMemoryArea {
//  private:
//   /** The address representing the end of the memory allocation. */
//   uint64_t vm_end = 0;
//   /** The address representing the start of the memory allocation. */
//   uint64_t vm_start = 0;
//   /** The next allocation in the contiguous list. */
//   VirtualMemoryArea* vm_next = nullptr;
//   /** The size of the virtual memory area. */
//   uint64_t length = 0;
// };

/** Class representing VMA linked list*/
class Vmall {
 private:
  /** Head of the VMA LinkedList. */
  VirtMemArea* vm_head_ = nullptr;

  /** Size of the VMA LinkedList. */
  size_t vm_size_ = 0;

 public:
  ~Vmall() {}
  /** This method adds a new VMA to the linked list.*/
  uint64_t addVma(VirtMemArea* vma, uint64_t mmapStart, uint64_t pageSize);

  /** This method removes a VMA at address "addr" from the linked list.*/
  int64_t removeVma(uint64_t addr, uint64_t length, uint64_t pageSize);

  /** This method returns the size of the linked list.*/
  size_t getSize();

  /** This method deletes the entire linked list. */
  void freeVma();
};

}  // namespace kernel
}  // namespace simeng