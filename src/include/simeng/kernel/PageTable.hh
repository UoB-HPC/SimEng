#pragma once
#include <map>
#include <memory>
#include <variant>
#include <vector>

#include "simeng/kernel/Masks.hh"

namespace TestFriends {
class PTFriend;
}

namespace simeng {
namespace kernel {

class PageTable {
  friend class TestFriends::PTFriend;
  using TableItr = typename std::map<uint64_t, uint64_t>::iterator;
  using IgnoredAddrRange = std::pair<uint64_t, uint64_t>;

 private:
  /** Size of each page in memory and page table entry. */
  const uint32_t pageSize_;
  /** Map used to store virtual to physical address mappings. */
  std::map<uint64_t, uint64_t> table_;
  /** Pair used to store ignored virtual address range. */
  IgnoredAddrRange ignored_ = std::pair<uint64_t, uint64_t>(0, 0);

  /** Method which creates a single page mapping between vaddr and paddr. */
  uint64_t allocatePTEntry(uint64_t alignedVAddr, uint64_t physAddr);

  /** Method which delete a single page mapping. */
  uint64_t deletePTEntry(PageTable::TableItr itr);

  /** Method which calculates the offset for vaddr to be added to base paddr. */
  uint64_t calculateOffset(uint64_t vaddr);

  /** Method to find page table entry associated with vaddr. */
  TableItr find(uint64_t vaddr);

 public:
  PageTable(uint64_t pageSize = 4096);
  ~PageTable();
  /** Method which creates size/pageSize number of mapping for vaddr & paddr. */
  uint64_t createMapping(uint64_t vaddr, uint64_t basePhyAddr, size_t size);

  /** Method which deletes size/pageSize number of mappings from vaddr. */
  uint64_t deleteMapping(uint64_t vaddr, size_t size);

  /** Method which checks if vaddr is mapped. */
  bool isMapped(uint64_t vaddr);

  /** Method which translates vaddr. */
  uint64_t translate(uint64_t vaddr);

  /** Method which adds address range to be ignored during translations. */
  void ignoreAddrRange(uint64_t startAddr, uint64_t endAddr);
};

}  // namespace kernel
}  // namespace simeng
