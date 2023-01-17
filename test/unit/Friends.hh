#pragma once
#include "simeng/kernel/PageFrameAllocator.hh"
namespace TestFriends {
class PFAFriend {
 public:
  simeng::kernel::PageFrameAllocator* allctr = NULL;
  PFAFriend(simeng::kernel::PageFrameAllocator* allctr) {
    this->allctr = allctr;
  }
  std::array<simeng::kernel::AllocEntry*, 16>& getEntries() {
    return allctr->entries_;
  };
};

}  // namespace TestFriends
