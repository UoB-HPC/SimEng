#include "simeng/kernel/Vma.hh"

namespace simeng {
namespace kernel {

uint64_t Vmall::addVma(VirtMemArea* vma, uint64_t mmapStart,
                       uint64_t pageSize) {
  if (vm_size_ > 1) {
    bool allocated = false;
    VirtMemArea* curr = vm_head_;
    while (curr != vm_tail_) {
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

int64_t Vmall::removeVma(uint64_t addr, uint64_t length, uint64_t pageSize) {
  if (addr % pageSize != 0) {
    // addr must be a multiple of the process page size
    return -1;
  }
  // Exit early if no entries
  if (vm_size_ == 0) {
    return 0;
  }
  VirtMemArea* prev = nullptr;
  VirtMemArea* curr = vm_head_;
  while (true) {
    if (curr->vm_start == addr) {
      if (curr->length < length) {
        // length must not be larger than the original allocation
        return -1;
      }
      // Removing only entry in list
      if (curr == vm_head_ && vm_head_ == vm_tail_) {
        free(curr);
        vm_head_ = nullptr;
        vm_tail_ = nullptr;
        vm_size_ = 0;
        break;
      }
      // Remove tail
      else if (curr == vm_tail_) {
        vm_tail_ = prev;
        prev->vm_next = nullptr;
        free(curr);
      }
      // We are removing the head.
      else if (curr == vm_head_) {
        vm_head_ = vm_head_->vm_next;
        curr->vm_next = nullptr;
        free(curr);
      } else {
        prev->vm_next = curr->vm_next;
        curr->vm_next = nullptr;
        free(curr);
      }
      vm_size_--;
      break;
    }
    if (curr == vm_tail_) {
      // Checked all possibly entries
      break;
    }
    prev = curr;
    curr = curr->vm_next;
  }
  // Not an error if the indicated range does no contain any mapped pages
  return 0;
}

void Vmall::freeVma() {
  if (vm_size_ == 0) return;
  VirtMemArea* curr = vm_head_;
  while (curr != vm_tail_) {
    VirtMemArea* temp = curr->vm_next;
    free(curr);
    curr = temp;
  }
  // Free vm_tail on own
  free(curr);
  vm_size_ = 0;
  vm_head_ = nullptr;
  vm_tail_ = nullptr;
}

size_t Vmall::getSize() { return vm_size_; }

}  // namespace kernel
}  // namespace simeng