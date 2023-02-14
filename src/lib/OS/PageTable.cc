#include "simeng/OS/PageTable.hh"

#include <cmath>
#include <iostream>
#include <vector>

#include "simeng/util/Math.hh"

namespace simeng {
namespace OS {

PageTable::PageTable(){};

PageTable::~PageTable(){};

bool PageTable::isMapped(uint64_t vaddr) { return find(vaddr) != table_.end(); }

uint64_t PageTable::generateOffsetMask(uint64_t pageSize) {
  if (!isPow2(page_size)) {
    std::cerr
        << "[SimEng:PageTable] Page size should be aligned to a power of 2."
        << std::endl;
    std::exit(1);
  }
  uint64_t lval = std::log2(page_size);
  uint64_t mask = 0;
  mask = ~mask;
  mask ^= (mask << lval);
  return mask;
}

PageTable::TableItr PageTable::find(uint64_t vaddr) {
  uint64_t lowestPageStart = downAlign(vaddr, page_size);
  TableItr itr = table_.find(lowestPageStart);
  return itr;
};

void PageTable::ignoreAddrRange(uint64_t startAddr, uint64_t endAddr) {
  ignored_ = std::pair<uint64_t, uint64_t>(startAddr, endAddr);
  return;
};

void PageTable::allocatePTEntry(uint64_t alignedVAddr, uint64_t phyAddr) {
  table_.insert(std::pair<uint64_t, uint64_t>(alignedVAddr, phyAddr));
};

void PageTable::deletePTEntry(PageTable::TableItr itr) { table_.erase(itr); };

uint64_t PageTable::calculateOffset(uint64_t vaddr) {
  // A mask of 0b0111111111111 to get the lower 12 bits of the vaddr.
  // The lower 12 bits of a vaddr will always be unique within a virtual address
  // because 2^12 = 4096. So we can return them as offsets to be added to a page
  // frame base addr. Page frames are also 4KB i.e 4096 Bytes so uniquess is
  // guarenteed.
  return vaddr & translationMask_;
};

uint64_t PageTable::createMapping(uint64_t vaddr, uint64_t basePhyAddr,
                                  size_t size) {
  // Round the address down to pageSize aligned value so we can map base
  // vaddr to base paddr.
  vaddr = downAlign(vaddr, page_size);
  // Round the size up to pageSize aligned value so we can map end vaddr to end
  // paddr.
  size = upAlign(size, page_size);
  uint64_t addr = vaddr;

  uint64_t vsize = size;
  while (vsize > 0) {
    PageTable::TableItr itr = table_.find(addr);
    if (itr != table_.end()) {
      return masks::faults::pagetable::fault | masks::faults::pagetable::map;
    }
    addr += page_size;
    vsize -= page_size;
  }

  addr = vaddr;
  while (size > 0) {
    allocatePTEntry(addr, basePhyAddr);
    addr += page_size;
    size -= page_size;
    basePhyAddr += page_size;
  }
  return vaddr;
};

uint64_t PageTable::deleteMapping(uint64_t vaddr, size_t size) {
  // Round the address down to pageSize aligned value so we can delete mapping
  // from base vaddr.
  vaddr = downAlign(vaddr, page_size);
  // Round the size up to pageSize aligned value so we can delete mapping to end
  // vaddr.
  size = upAlign(size, page_size);
  uint64_t addr = vaddr;
  std::vector<PageTable::TableItr> itrs;

  while (size > 0) {
    auto itr = table_.find(addr);
    if (itr == table_.end()) {
      return masks::faults::pagetable::fault | masks::faults::pagetable::unmap;
    }
    addr += page_size;
    size -= page_size;
    itrs.push_back(itr);
  }

  for (auto itr : itrs) {
    deletePTEntry(itr);
  };

  return 0;
};

uint64_t PageTable::translate(uint64_t vaddr) {
  if (vaddr >= ignored_.first && vaddr < ignored_.second) {
    return masks::faults::pagetable::fault | masks::faults::pagetable::ignored;
  }
  TableItr entry = find(vaddr);
  if (entry == table_.end()) {
    return masks::faults::pagetable::fault |
           masks::faults::pagetable::translate;
  }
  uint64_t addr = entry->second + calculateOffset(vaddr);
  return addr;
};

}  // namespace OS
}  // namespace simeng
