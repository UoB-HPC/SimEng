#pragma once
#include <map>
#include <memory>
#include <unordered_map>
#include <variant>

#include "simeng/kernel/Masks.hh"

namespace TestFriends {
class PTFriend;
}

namespace simeng {
namespace OS {

class PageTable {
  friend class TestFriends::PTFriend;
  using TableItr = typename std::map<uint64_t, uint64_t>::iterator;

 private:
  const uint32_t pageSize_ = 4096;
  std::map<uint64_t, uint64_t> table_;

  uint64_t allocatePTEntry(uint64_t alignedVAddr, uint64_t physAddr);
  uint64_t deletePTEntry(PageTable::TableItr itr);
  uint64_t calculateOffset(uint64_t vaddr);
  TableItr find(uint64_t vaddr);

 public:
  PageTable();
  ~PageTable();
  uint64_t createMapping(uint64_t vaddr, uint64_t basePhyAddr, size_t size);
  uint64_t deleteMapping(uint64_t vaddr, size_t size);
  bool isMapped(uint64_t vaddr);
  uint64_t translate(int64_t vaddr);
};

}  // namespace OS
}  // namespace simeng
