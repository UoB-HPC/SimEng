#pragma once
#include "simeng/kernel/PageFrameAllocator.hh"
#include "simeng/kernel/PageTable.hh"
#include "simeng/kernel/Vma.hh"

namespace TestFriends {
/*
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
*/

class HBFMFriend {
 public:
  simeng::kernel::HostBackedFileMMaps* fmap = NULL;
  HBFMFriend(simeng::kernel::HostBackedFileMMaps* ptr) { fmap = ptr; };
  std::vector<simeng::kernel::HostFileMMap*> getHostVector() {
    return fmap->hostvec;
  };
};

class PTFriend {
 public:
  simeng::kernel::PageTable* pTable = NULL;
  PTFriend(simeng::kernel::PageTable* ptable) { pTable = ptable; };
  std::map<uint64_t, uint64_t>& getTable() { return pTable->table_; }
};

}  // namespace TestFriends
