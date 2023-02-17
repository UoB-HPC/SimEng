#pragma once
#include <map>
#include <memory>
#include <variant>
#include <vector>

#include "simeng/OS/Constants.hh"

namespace TestFriends {
class PTFriend;
}

namespace simeng {
namespace OS {

using namespace simeng::OS::defaults;

class PageTable {
  // Friend class declaration so private members can be accessed in the test
  // suite.
  friend class TestFriends::PTFriend;
  using TableItr = typename std::map<uint64_t, uint64_t>::iterator;
  using IgnoredAddrRange = std::pair<uint64_t, uint64_t>;

 public:
  PageTable();

  ~PageTable();

  /** Method which creates size/pageSize number of mappings for vaddr &
   * basePhyAddr. */
  uint64_t createMapping(uint64_t vaddr, uint64_t basePhyAddr, size_t size);

  /** Method which deletes size/pageSize number of mappings from vaddr. */
  uint64_t deleteMapping(uint64_t vaddr, size_t size);

  /** Method which checks if vaddr is mapped. */
  bool isMapped(uint64_t vaddr);

  /** Method which translates a virtual address into physical address to be used
   * for memory operations. */
  uint64_t translate(uint64_t vaddr);

  /** Method which adds an address range to be ignored during translations. */
  void ignoreAddrRange(uint64_t startAddr, uint64_t endAddr);

 private:
  /** Offset mask used to retrive 12 lsb of the virtual address. */
  const uint64_t translationMask_ = generateOffsetMask(page_size);

  /** Map used to store virtual to physical address mappings. */
  std::map<uint64_t, uint64_t> table_;

  /** Pair used to store ignored virtual address range. */
  IgnoredAddrRange ignored_ = std::pair<uint64_t, uint64_t>(0, 0);

  /** Method which creates a single page mapping between alignedVAddr and
   * physAddr. */
  void allocatePTEntry(uint64_t alignedVAddr, uint64_t physAddr);

  /** Method which delete a single page mapping. */
  void deletePTEntry(PageTable::TableItr itr);

  /** Method which calculates the offset for vaddr to be added to base paddr. */
  uint64_t calculateOffset(uint64_t vaddr);

  /** Method to the find page table entry associated with vaddr. */
  TableItr find(uint64_t vaddr);

  /** This method generates an offset mask based on the page size. */
  uint64_t generateOffsetMask(uint64_t pageSize);
};

}  // namespace OS
}  // namespace simeng
