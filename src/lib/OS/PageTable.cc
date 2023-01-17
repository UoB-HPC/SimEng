#include "simeng/OS/PageTable.hh"

#include <iostream>

#include "simeng/util/Math.hh"

namespace simeng {
namespace OS {

PageTable::PageTable() {
  table_ = std::shared_ptr<std::map<uint64_t, simeng::kernel::PTEntry*>>(
      new std::map<uint64_t, simeng::kernel::PTEntry*>);
};

PageTable::~PageTable(){};

bool PageTable::isMapped(uint64_t vaddr) {
  return find(vaddr) != table_->end();
}

PageTable::TableItr PageTable::find(uint64_t vaddr) {
  uint64_t lowestPageStart = roundDownMemAddr(vaddr, pageSize_);
  TableItr itr = table_->find(lowestPageStart);
  return itr;
};

uint64_t PageTable::allocatePTEntry(uint64_t vaddr, uint64_t phyAddr) {
  TableItr mapped = find(vaddr);
  if (mapped != table_->end()) {
    std::cerr << "Mapping already exists for virtual address: " << vaddr
              << std::endl;
    return mapped->second->baseVAddr;
  };
  uint64_t alignedAddr = roundDownMemAddr(vaddr, pageSize_);
  PTEntry* entry = new PTEntry{alignedAddr, phyAddr, alignedAddr + 4096};
  table_->insert(std::pair<uint64_t, PTEntry*>(alignedAddr, entry));
  return alignedAddr;
};

uint64_t PageTable::deletePTEntry(uint64_t vaddr) {
  TableItr mapped = find(vaddr);
  if (mapped != table_->end()) {
    std::cerr << "Mapping does not exist for virtual address: " << vaddr
              << std::endl;
    return ~0;
  };
  PTEntry* entry = mapped->second;
  uint64_t addr = entry->baseVAddr;
  table_->erase(mapped);
  delete entry;
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

bool PageTable::createMapping(uint64_t vaddr, uint64_t basePhyAddr,
                              size_t size) {
  uint64_t addr = vaddr;
  size = roundUpMemAddr(size, 4096);
  while (size > 0) {
    addr = allocatePTEntry(addr, basePhyAddr);
    if (addr == ~(uint64_t)0) {
      std::cerr << "Couldn't create Mapping!" << std::endl;
      return false;
    }
    addr += pageSize_;
    size -= pageSize_;
    basePhyAddr += pageSize_;
  }
  return true;
};

bool PageTable::deleteMapping(uint64_t vaddr, size_t size) {
  uint64_t addr = vaddr;
  size = roundUpMemAddr(size, 4096);
  while (size > 0) {
    addr = deletePTEntry(addr);
    if (addr == ~(uint64_t)0) {
      std::cerr << "Couldn't delete Mapping!" << std::endl;
      return false;
    }
    addr += pageSize_;
    size -= pageSize_;
  }
  return true;
};

uint64_t PageTable::translate(int64_t vaddr) {
  TableItr entry = find(vaddr);
  if (entry != table_->end()) {
    std::cerr << "Mapping doesn't exist for virtual address: " << vaddr
              << std::endl;
    // Signify fault by using 2^64 as the value.
    return ~0;
  }
  return entry->second->basePhyAddr + calculateOffset(vaddr);
};

}  // namespace OS
}  // namespace simeng
