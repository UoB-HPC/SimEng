#pragma once
#include "simeng/OS/PageFrameAllocator.hh"
#include "simeng/OS/PageTable.hh"
#include "simeng/OS/Vma.hh"

namespace TestFriends {
class PTFriend {
 public:
  simeng::OS::PageTable* pTable = NULL;
  PTFriend(simeng::OS::PageTable* ptable) { pTable = ptable; };
  ~PTFriend() { delete pTable; }
  std::map<uint64_t, uint64_t>& getTable() { return pTable->table_; }
};

}  // namespace TestFriends
