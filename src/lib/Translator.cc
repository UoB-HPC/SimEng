#include "simeng/Translator.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace simeng {

Translator::Translator() {
  mappings = std::unordered_map<memoryRegion, memoryRegion, hash_fn>();
}

Translator::~Translator() {}

const Translation Translator::get_mapping(uint64_t addr) const {
  auto res = std::find_if(
      mappings.begin(), mappings.end(),
      [&](const std::pair<memoryRegion, memoryRegion>& mem) {
        return (addr >= mem.first.addr_start && addr < mem.first.addr_end);
      });
  if (res != mappings.end()) {
    return {(addr - res->first.addr_start) + res->second.addr_start, true};
  }
  return {0, false};
}

bool Translator::add_mapping(memoryRegion a, memoryRegion b) {
  // std::cout << "# New mapping:\n 0x" << std::hex << a.addr_start << std::dec
  //           << ":0x" << std::hex << a.addr_end << std::dec << " -> ";
  // Ensure translated block is the same size as the original
  if ((a.addr_end - a.addr_start) != (b.addr_end - b.addr_start)) {
    // std::cout << "diff size (" << (a.addr_end - a.addr_start) << " vs "
    //           << (b.addr_end - b.addr_start) << ")" << std::endl;
    // assert(false && "Differently sized memory regions");
    return false;
  }
  // std::min used to ensure boundaries compared against don't wrap around to
  // unsigned(-1)
  auto res = std::find_if(
      mappings.begin(), mappings.end(),
      [&](const std::pair<memoryRegion, memoryRegion>& mem) {
        return !(b.addr_start > std::min(mem.second.addr_end - 1, 0ull) ||
                 std::min(b.addr_end - 1, 0ull) < mem.second.addr_start);
      });
  if (res != mappings.end()) {
    // std::cout << "Overlap:" << std::endl;
    // std::cout << "\t0x" << std::hex << res->second.addr_start << std::dec
    //           << " to 0x" << std::hex << res->second.addr_end << std::dec
    //           << std::endl;
    // std::cout << "\t0x" << std::hex << b.addr_start << std::dec << " to 0x"
    //           << std::hex << b.addr_end << std::dec << std::endl;
    // assert(false && "Overlaps with previously allocated region");
    return false;
  }

  mappings.insert({a, b});

  // std::cout << "0x" << std::hex << b.addr_start << std::dec << ":0x" <<
  // std::hex
  //           << b.addr_end << std::dec << std::endl;
  return true;
}

bool Translator::update_mapping(memoryRegion a, memoryRegion b,
                                memoryRegion c) {
  // std::cout << "# Update mapping:\n 0x" << std::hex << a.addr_start <<
  // std::dec
  //           << ":0x" << std::hex << a.addr_end << std::dec << "("
  //           << (a.addr_end - a.addr_start) << ") = 0x" << std::hex
  //           << b.addr_start << std::dec << ":0x" << std::hex << b.addr_end
  //           << std::dec << "(" << (b.addr_end - b.addr_start) << ") -> ";
  // Ensure translated block is the same size as the original
  if ((b.addr_end - b.addr_start) != (c.addr_end - c.addr_start)) {
    // std::cout << "diff size (" << (b.addr_end - b.addr_start) << " vs "
    //           << (c.addr_end - c.addr_start) << ")" << std::endl;
    return false;
  }
  // Ensure old program region exists
  auto res_old =
      std::find_if(mappings.begin(), mappings.end(),
                   [&](const std::pair<memoryRegion, memoryRegion>& mem) {
                     return (a.addr_start == mem.first.addr_start &&
                             a.addr_end == mem.first.addr_end);
                   });
  if (res_old == mappings.end()) {
    // std::cout << "original doesn't exist" << std::endl;
    return false;
  }

  std::pair<memoryRegion, memoryRegion> temp = *res_old;
  mappings.erase(res_old);

  // std::cout << "Found entry 0x" << std::hex << temp.first.addr_start <<
  // std::dec
  //           << " to 0x" << std::hex << temp.first.addr_end << std::dec
  //           << " -> ";

  // Ensure new simeng region shares no boundary with previous mappings
  // std::min used to ensure boundaries compared against don't wrap around
  // to unsigned(-1)
  auto res = std::find_if(
      mappings.begin(), mappings.end(),
      [&](const std::pair<memoryRegion, memoryRegion>& mem) {
        return !(c.addr_start > std::min(mem.second.addr_end - 1, 0ull) ||
                 std::min(c.addr_end - 1, 0ull) < mem.second.addr_start);
      });
  if (res != mappings.end()) {
    // std::cout << "overlaps prior region 0x" << std::hex
    //           << res->second.addr_start << std::dec << ":0x" << std::hex
    //           << res->second.addr_end << std::dec << " <- 0x" << std::hex
    //           << c.addr_start << std::dec << ":0x" << std::hex << c.addr_end
    //           << std::dec << std::endl;
    mappings.insert(temp);
    return false;
  }
  // Add new mapping
  mappings.insert({b, c});
  // std::cout << "0x" << std::hex << temp.second.addr_start << std::dec <<
  // ":0x"
  //           << std::hex << temp.second.addr_end << std::dec << "("
  //           << (temp.second.addr_end - temp.second.addr_start) << ") = 0x"
  //           << std::hex << c.addr_start << std::dec << ":0x" << std::hex
  //           << c.addr_end << std::dec << "(" << (c.addr_end - c.addr_start)
  //           << ")" << std::endl;

  return true;
}

uint64_t Translator::mmap_allocation(size_t length) {
  std::shared_ptr<struct heap_allocation> newAlloc(new heap_allocation);
  memoryRegion previousAllocation = {0, 0};
  // Find suitable region to allocate
  for (heap_allocation& alloc : heapAllocations_) {
    // Determine if the new allocation can fit between existing allocations.
    // Append to end of allocations if not
    if (alloc.next != NULL && (alloc.next->start - alloc.end) >= length) {
      // '- 2' to ensure allocation doesn't overlap with prior allocation
      // boundaries
      newAlloc->start = alloc.end;
      uint64_t region_start = alloc.mapped_region.addr_end;
      newAlloc->mapped_region.addr_start = region_start;
      // Re-link contiguous allocation to include new allocation
      newAlloc->next = alloc.next;
      alloc.next = newAlloc;
      break;
    }
  }
  if (newAlloc->start == 0) {
    if (heapAllocations_.size()) {
      // Append allocation to end of list and link first entry to new
      newAlloc->start = heapAllocations_.back().end;
      uint64_t region_start = heapAllocations_.back().mapped_region.addr_end;
      newAlloc->mapped_region.addr_start = region_start;
      heapAllocations_.back().next = newAlloc;
    } else {
      // If no allocations exists, allocate to start of the process mmap region
      newAlloc->start = heapStarts_.first;
      newAlloc->mapped_region.addr_start = heapStarts_.second;
    }
  }
  newAlloc->end = newAlloc->start + length;
  // '- 1' from region end as bound is exclusive
  newAlloc->mapped_region.addr_end =
      newAlloc->mapped_region.addr_start + length;
  // The end of the allocation must be
  // rounded up to the nearest page size
  uint64_t remainder = (newAlloc->start + length) % pageSize_;
  newAlloc->end += (remainder != 0) ? (pageSize_ - remainder) : 0;
  newAlloc->mapped_region.addr_end +=
      (remainder != 0) ? (pageSize_ - remainder) : 0;

  // std::cout << "Allocation:" << std::endl;
  // std::cout << "\t0x" << std::hex << newAlloc->start << std::dec << " to 0x"
  //           << std::hex << newAlloc->end << std::dec << std::endl;
  // std::cout << "\t0x" << std::hex << newAlloc->mapped_region.addr_start
  //           << std::dec << " to 0x" << std::hex
  //           << newAlloc->mapped_region.addr_end << std::dec << std::endl;

  // Register new allocation/region

  add_mapping({newAlloc->start, newAlloc->end}, newAlloc->mapped_region);
  heapAllocations_.push_back(*newAlloc);

  return newAlloc->start;
}

int64_t Translator::munmap_deallocation(uint64_t addr, size_t length) {
  if (addr % pageSize_ != 0) {
    // addr must be a multiple of the process page size
    return -1;
  }

  heap_allocation alloc;
  // Find addr in allocations
  for (int i = 0; i < heapAllocations_.size(); i++) {
    alloc = heapAllocations_[i];
    if (alloc.start == addr) {
      if ((alloc.end - alloc.start) < length) {
        // length must not be larger than the original allocation as munmap
        // across multiple pages is not supported
        return -1;
      }
      // Fix next values to not include to-be erased entry
      if (i != 0) {
        heapAllocations_[i - 1].next = heapAllocations_[i].next;
      }
      // Ensure program region exists in mappings
      auto res_old = std::find_if(
          mappings.begin(), mappings.end(),
          [&](const std::pair<memoryRegion, memoryRegion>& mem) {
            return (alloc.mapped_region.addr_start == mem.first.addr_start &&
                    alloc.mapped_region.addr_end == mem.first.addr_end);
          });
      if (res_old == mappings.end()) {
        // std::cout << "original doesn't exist" << std::endl;
        return -1;
      }
      // Erase allocation/region entries
      mappings.erase(alloc.mapped_region);
      heapAllocations_.erase(heapAllocations_.begin() + i);
      return 0;
    }
  }
  // Not an error if the indicated range does no contain any mapped pages
  return 0;
}

void Translator::setHeapStart(uint64_t processAddress,
                              uint64_t simulationAddress) {
  heapStarts_ = {processAddress, simulationAddress};
}

void Translator::setPageSize(uint64_t pagesize) { pageSize_ = pagesize; }

}  // namespace simeng
