#include "simeng/OS/PageTable.hh"

#include <iostream>
#include <vector>

#include "simeng/util/Math.hh"

namespace simeng {
namespace OS {

bool PageTable::isMapped(uint64_t vaddr) { return find(vaddr) != table_.end(); }

uint64_t PageTable::generateOffsetMask(uint64_t pageSize) {
  if (!isPow2(pageSize)) {
    std::cerr
        << "[SimEng:PageTable] Page size should be aligned to a power of 2."
        << std::endl;
    std::exit(1);
  }
  // Given that pageSize is a power of 2, pageSize - 1 will have log2(pageSize)
  // number of lowest significant bits as 1. This mask will allow us to extract
  // log2(pageSize) number of lowest significant bits from a virtual address.
  // The bits extracted will always be unique within a virtual address range of
  // 'pageSize' bytes.
  return pageSize - 1;
}

PageTable::TableItr PageTable::find(uint64_t vaddr) {
  uint64_t lowestPageStart = downAlign(vaddr, PAGE_SIZE);
  TableItr itr = table_.find(lowestPageStart);
  return itr;
}

void PageTable::ignoreAddrRange(uint64_t startAddr, uint64_t endAddr) {
  ignoredAddrRange_ = std::pair<uint64_t, uint64_t>(startAddr, endAddr);
  return;
}

void PageTable::allocatePTEntry(uint64_t alignedVAddr, uint64_t phyAddr) {
  table_.insert(std::pair<uint64_t, uint64_t>(alignedVAddr, phyAddr));
}

void PageTable::deletePTEntry(PageTable::TableItr itr) { table_.erase(itr); }

uint64_t PageTable::calculateOffset(uint64_t vaddr) {
  // TODO: Replace the comment below with a generic comment once user-specified
  // page sizes are supported in SimEng.
  // Currently SimEng only supports a page size of 4096 bytes, so a mask of
  // 0b0111111111111 will allow us to extract the lower 12 bits of the vaddr.
  // The lower 12 bits of a vaddr will always be unique within a virtual address
  // because 2^12 = 4096. So we can return them as offsets to be added to a page
  // frame base addr. Page frames are also 4KB i.e 4096 Bytes so uniqueness is
  // guarenteed.
  return vaddr & translationMask_;
}

uint64_t PageTable::createMapping(uint64_t vaddr, uint64_t basePhyAddr,
                                  size_t size) {
  // Round the address down to pageSize aligned value so we can map base
  // vaddr to base paddr.
  vaddr = downAlign(vaddr, PAGE_SIZE);
  // Round the size up to pageSize aligned value so we can map end vaddr to end
  // paddr.
  size = upAlign(size, PAGE_SIZE);
  uint64_t addr = vaddr;

  // Increment down aligned vaddr by PAGE_SIZE every loop iteration until
  // (size / PAGE_SIZE)  number of address ranges haves been convered. In each
  // loop iteration check if address range is unmapped, if not return a page
  // table fault.
  uint64_t vsize = size;
  while (vsize > 0) {
    PageTable::TableItr itr = table_.find(addr);
    if (itr != table_.end()) {
      return masks::faults::pagetable::FAULT | masks::faults::pagetable::MAP;
    }
    addr += PAGE_SIZE;
    vsize -= PAGE_SIZE;
  }

  addr = vaddr;
  // Increment down aligned vaddr by PAGE_SIZE every loop iteration and
  // allocate a page table entry for each address range.
  while (size > 0) {
    allocatePTEntry(addr, basePhyAddr);
    addr += PAGE_SIZE;
    size -= PAGE_SIZE;
    basePhyAddr += PAGE_SIZE;
  }
  return vaddr;
}

uint64_t PageTable::deleteMapping(uint64_t vaddr, size_t size) {
  // Round the address down to pageSize aligned value so we can delete mapping
  // from base vaddr.
  vaddr = downAlign(vaddr, PAGE_SIZE);
  // Round the size up to pageSize aligned value so we can delete mapping to end
  // vaddr.
  size = upAlign(size, PAGE_SIZE);
  std::vector<PageTable::TableItr> itrs;

  // Increment down aligned vaddr by PAGE_SIZE every loop iteration until
  // (size / PAGE_SIZE) number of address ranges have been covered.
  while (size > 0) {
    auto itr = table_.find(vaddr);
    if (itr != table_.end()) {
      itrs.push_back(itr);
    }
    vaddr += PAGE_SIZE;
    size -= PAGE_SIZE;
  }

  for (auto itr : itrs) {
    deletePTEntry(itr);
  }

  return 0;
}

uint64_t PageTable::translate(uint64_t vaddr) {
  if (vaddr >= ignoredAddrRange_.first && vaddr < ignoredAddrRange_.second) {
    return masks::faults::pagetable::FAULT | masks::faults::pagetable::IGNORED;
  }
  TableItr entry = find(vaddr);
  if (entry == table_.end()) {
    return masks::faults::pagetable::FAULT |
           masks::faults::pagetable::TRANSLATE;
  }
  uint64_t addr = entry->second + calculateOffset(vaddr);
  return addr;
}

std::map<uint64_t, uint64_t> PageTable::getTable() { return table_; }

}  // namespace OS
}  // namespace simeng
