#pragma once
#include <map>
#include <memory>

namespace TestFriends {
class PTFriend;
}

namespace simeng {
namespace kernel {

struct PTEntry {
  uint64_t baseVAddr;
  uint64_t basePhyAddr;
  uint64_t endVAddr;
};

class PageTable {
  friend class TestFriends::PTFriend;
  using TableItr = typename std::map<uint64_t, PTEntry*>::iterator;

 private:
  const uint32_t pageSize_ = 4096;
  std::shared_ptr<std::map<uint64_t, PTEntry*>> table_;

  uint64_t allocatePTEntry(uint64_t vaddr, uint64_t physAddr);
  uint64_t deletePTEntry(uint64_t vaddr);
  uint64_t calculateOffset(uint64_t vaddr);
  TableItr find(uint64_t vaddr);

 public:
  PageTable();
  ~PageTable();
  bool createMapping(uint64_t vaddr, uint64_t basePhyAddr, size_t size);
  bool deleteMapping(uint64_t vaddr, size_t size);
  bool isMapped(uint64_t vaddr);
  uint64_t translate(int64_t vaddr);
};

}  // namespace kernel
}  // namespace simeng
