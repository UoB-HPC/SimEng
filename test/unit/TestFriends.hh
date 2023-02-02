#pragma once
#include "simeng/kernel/PageFrameAllocator.hh"
#include "simeng/kernel/PageTable.hh"
#include "simeng/kernel/Vma.hh"

namespace TestFriends {
class PTFriend {
 public:
  simeng::kernel::PageTable* pTable = NULL;
  PTFriend(simeng::kernel::PageTable* ptable) { pTable = ptable; };
  std::map<uint64_t, uint64_t>& getTable() { return pTable->table_; }
};

}  // namespace TestFriends
