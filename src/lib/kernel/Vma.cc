#include "simeng/kernel/Vma.hh"

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
    if (!allocated) {
      vma->vm_start = curr->vm_end;
      curr->vm_next = vma;
    }
  } else if (vm_size_ > 0) {
    vma->vm_start = vm_head_->vm_end;
    vm_head_->vm_next = vma;
  } else {
    vma->vm_start = mmapStart;
    vm_head_ = vma;
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
  while (curr != nullptr) {
    if (curr->vm_start == addr) {
      if (curr->length < length) {
        // length must not be larger than the original allocation
        return -1;
      }
      // Removing the head
      if (prev == nullptr) {
        vm_head_ = vm_head_->vm_next;
        curr->vm_next = nullptr;
        delete curr;
      } else {
        prev->vm_next = curr->vm_next;
        curr->vm_next = nullptr;
        delete curr;
      }
      vm_size_--;
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
  while (curr != nullptr) {
    VirtMemArea* temp = curr->vm_next;
    delete curr;
    curr = temp;
  }
  vm_size_ = 0;
  vm_head_ = nullptr;
}

size_t Vmall::getSize() { return vm_size_; }

}  // namespace kernel
}  // namespace simeng