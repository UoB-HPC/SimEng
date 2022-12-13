#include "simeng/kernel/Vma.hh"

#include <iostream>

#include "simeng/util/Math.hh"

namespace simeng {
namespace kernel {

uint64_t Vmall::addVma(VirtMemArea* vma, uint64_t mmapStart,
                       uint64_t pageSize) {
  if (vm_size_ > 1) {
    bool allocated = false;
    VirtMemArea* curr = vm_head_;
    while (curr->vm_next != nullptr) {
      if (curr->vm_next->vm_start - curr->vm_end >= vma->length) {
        vma->vm_start = curr->vm_end;
        vma->vm_next = curr->vm_next;
        curr->vm_next = vma;
        allocated = true;
        break;
      }
      curr = curr->vm_next;
    }
    // We are at the tail
    if (!allocated && vm_tail_ == curr) {
      vma->vm_start = vm_tail_->vm_end;
      vm_tail_->vm_next = vma;
      vm_tail_ = vma;
    }

  } else if (vm_size_ > 0) {
    vma->vm_start = vm_head_->vm_end;
    vm_head_->vm_next = vma;
    vm_tail_ = vma;
  } else {
    vma->vm_start = mmapStart;
    vm_head_ = vma;
    vm_tail_ = vm_head_;
  }
  vma->vm_end = roundUpMemAddr(vma->vm_start + vma->length, pageSize);
  vm_size_++;
  return vma->vm_start;
}

void Vmall::removeVma(uint64_t addr, uint64_t length, uint64_t pageSize) {
  if (addr % pageSize != 0) {
    std::cerr << "[SimEng:Vma] Cannot remove Virtual memory area: VirtMemArea "
                 "start address is not page aligned."
              << std::endl;
    std::exit(1);
  }
  VirtMemArea* prev = nullptr;
  VirtMemArea* curr = vm_head_;
  while (curr != nullptr) {
    if (curr->vm_start == addr) {
      if (curr->length < length) {
        std::cerr << "[SimEng:Vma] Cannot remove Virtual memory area: "
                     "Specified length ("
                  << length << ") is greater than VirtMemArea length ("
                  << curr->length << ") is not page aligned." << std::endl;
        std::exit(1);
      }
      // We are removing the head.
      if (prev == nullptr) {
        vm_head_ = vm_head_->vm_next;
        curr->vm_next = nullptr;
        free(curr);
      } else {
        if (curr == vm_tail_) {
          vm_tail_ = prev;
        }
        prev->vm_next = curr->vm_next;
        curr->vm_next = nullptr;
        free(curr);
      }
      vm_size_--;
      break;
    }
    prev = curr;
    curr = curr->vm_next;
  }
}

void Vmall::freeVma() {
  if (vm_size_ == 0) return;
  VirtMemArea* curr = vm_head_;
  while (curr != nullptr) {
    VirtMemArea* temp = curr->vm_next;
    free(curr);
    curr = temp;
  }
  vm_size_ = 0;
  vm_head_ = nullptr;
  vm_tail_ = nullptr;
}

size_t Vmall::getSize() { return vm_size_; }

}  // namespace kernel
}  // namespace simeng