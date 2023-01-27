#include "simeng/OS/PageTable.hh"

#include <iostream>
#include <vector>

#include "simeng/util/Math.hh"

namespace simeng {
namespace OS {

PageTable::PageTable(){};

PageTable::~PageTable(){};

bool PageTable::isMapped(uint64_t vaddr) { return find(vaddr) != table_.end(); }

PageTable::TableItr PageTable::find(uint64_t vaddr) {
  uint64_t lowestPageStart = roundDownMemAddr(vaddr, pageSize_);
  TableItr itr = table_.find(lowestPageStart);
  return itr;
};

uint64_t PageTable::allocatePTEntry(uint64_t alignedVAddr, uint64_t phyAddr) {
  table_.insert(std::pair<uint64_t, uint64_t>(alignedVAddr, phyAddr));
  return alignedVAddr;
};

uint64_t PageTable::deletePTEntry(PageTable::TableItr itr) {
  uint64_t addr = itr->second;
  table_.erase(itr);
  return addr;
};

uint64_t PageTable::calculateOffset(uint64_t vaddr) {
  uint64_t mask = 0xFFF;
  // A mask of 0b0111111111111 to get the lower 12 bits of the vaddr.
  // The lower 12 bits of a vaddr will always be unique within a virtual address
  // because 2^12 = 4096. So we can return them as offsets to be added to a page
  // frame base addr. Page frames are also 4KB i.e 4096 Bytes so uniquess is
  // guarenteed.
  return vaddr & mask;
};

uint64_t PageTable::createMapping(uint64_t vaddr, uint64_t basePhyAddr,
                                  size_t size) {
  vaddr = roundDownMemAddr(vaddr, pageSize_);
  size = roundUpMemAddr(size, pageSize_);
  uint64_t addr = vaddr;

  uint64_t vsize = size;
  while (vsize > 0) {
    PageTable::TableItr itr = table_.find(addr);
    if (itr != table_.end()) {
      return masks::faults::pagetable::fault | masks::faults::pagetable::map;
    }
    addr += pageSize_;
    vsize -= pageSize_;
  }

  addr = vaddr;
  while (size > 0) {
    addr = allocatePTEntry(addr, basePhyAddr);
    addr += pageSize_;
    size -= pageSize_;
    basePhyAddr += pageSize_;
  }
  return vaddr;
};

uint64_t PageTable::deleteMapping(uint64_t vaddr, size_t size) {
  vaddr = roundDownMemAddr(vaddr, pageSize_);
  size = roundUpMemAddr(size, pageSize_);
  uint64_t addr = vaddr;
  std::vector<PageTable::TableItr> itrs;

  while (size > 0) {
    auto itr = table_.find(addr);
    if (itr == table_.end()) {
      return masks::faults::pagetable::fault | masks::faults::pagetable::unmap;
    }
    addr += pageSize_;
    size -= pageSize_;
    itrs.push_back(itr);
  }

  for (auto itr : itrs) {
    deletePTEntry(itr);
  };

  return 0;
};

uint64_t PageTable::translate(int64_t vaddr) {
  TableItr entry = find(vaddr);
  if (entry == table_.end()) {
    // std::cerr << "Mapping doesn't exist for virtual address: " << vaddr
    //       << std::endl;
    return masks::faults::pagetable::fault |
           masks::faults::pagetable::translate;
    // Signify fault by using 2^64 as the value.
  }
  uint64_t addr = entry->second + calculateOffset(vaddr);
  return addr;
};

}  // namespace OS
}  // namespace simeng
