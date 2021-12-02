#include "simeng/Translator.hh"

#include <algorithm>
#include <iostream>

namespace simeng {

typedef std::unordered_map<uint64_t, uint64_t> stringmap;

void Translator::enumerate_region(memoryRegion region_process,
                                  memoryRegion region_simulation, bool insert) {
  if (!disableTranslation_) {
    if (insert) {
      for (int i = 0; i < (region_process.addr_end - region_process.addr_start);
           i++) {
        mappings_[region_process.addr_start + i] =
            region_simulation.addr_start + i;
      }
    } else {
      for (int i = 0; i < (region_process.addr_end - region_process.addr_start);
           i++) {
        mappings_.erase({region_process.addr_start + i});
      }
    }
  }
}

Translator::Translator() {
  mappings_ = std::unordered_map<uint64_t, uint64_t>();
  regions_ = std::unordered_map<memoryRegion, memoryRegion, hash_fn>();
}

Translator::~Translator() {}

const Translation Translator::get_mapping(uint64_t addr) const {
  if (disableTranslation_) {
    return {addr, true};
  }
  // auto searched_region = std::find_if(
  //     regions_.begin(), regions_.end(),
  //     [&](const std::pair<memoryRegion, memoryRegion>& mem) {
  //       return (addr >= mem.first.addr_start && addr < mem.first.addr_end);
  //     });
  // if (searched_region != regions_.end()) {
  //   return {(addr - searched_region->first.addr_start) +
  //   searched_region->second.addr_start, true};
  // }
  // return {0, false};
  try {
    return {mappings_.at(addr), true};
  } catch (const std::out_of_range& e) {
    // std::cout << "FAILED to get mapping for 0x" << std::hex << addr <<
    // std::dec
    //           << std::endl;
    return {0, false};
  }
}

bool Translator::add_mapping(memoryRegion region_process,
                             memoryRegion region_simulation) {
  if (disableTranslation_) return true;
  // std::cout << "# New mapping:\n 0x" << std::hex << region_process.addr_start
  //           << std::dec << ":0x" << std::hex << region_process.addr_end
  //           << std::dec << " -> ";
  // Ensure provided region boundaries are valid
  if (region_process.addr_start >= region_process.addr_end ||
      region_simulation.addr_start >= region_simulation.addr_end) {
    // std::cout << "invalid region" << std::endl;
    return false;
  }

  // Ensure translated block is the same size as the original
  if ((region_process.addr_end - region_process.addr_start) !=
      (region_simulation.addr_end - region_simulation.addr_start)) {
    // std::cout << "diff size ("
    //           << (region_process.addr_end - region_process.addr_start) << "
    //           vs "
    //           << (region_simulation.addr_end - region_simulation.addr_start)
    //           << ")" << std::endl;
    return false;
  }

  // Ensure new program region shares no boundary with previous process region
  // std::max used to ensure boundaries of 0 don't wrap around to unsigned(-1)
  auto searched_region =
      std::find_if(regions_.begin(), regions_.end(),
                   [&](const std::pair<memoryRegion, memoryRegion>& mem) {
                     return !(region_process.addr_start >
                                  (std::max(mem.first.addr_end, 1ull) - 1) ||
                              (std::max(region_process.addr_end, 1ull) - 1) <
                                  mem.first.addr_start);
                   });
  if (searched_region != regions_.end()) {
    // std::cout << "Overlap:" << std::endl;
    // std::cout << "\t0x" << std::hex << searched_region->first.addr_start
    //           << std::dec << " to 0x" << std::hex
    //           << searched_region->first.addr_end << std::dec << std::endl;
    // std::cout << "\t0x" << std::hex << region_process.addr_start << std::dec
    //           << " to 0x" << std::hex << region_process.addr_end << std::dec
    //           << std::endl;
    return false;
  }
  // Ensure new simeng region shares no boundary with previous simeng region
  searched_region =
      std::find_if(regions_.begin(), regions_.end(),
                   [&](const std::pair<memoryRegion, memoryRegion>& mem) {
                     return !(region_simulation.addr_start >
                                  (std::max(mem.second.addr_end, 1ull) - 1) ||
                              (std::max(region_simulation.addr_end, 1ull) - 1) <
                                  mem.second.addr_start);
                   });
  if (searched_region != regions_.end()) {
    // std::cout << "Overlap:" << std::endl;
    // std::cout << "\t0x" << std::hex << searched_region->second.addr_start
    //           << std::dec << " to 0x" << std::hex
    //           << searched_region->second.addr_end << std::dec << std::endl;
    // std::cout << "\t0x" << std::hex << region_simulation.addr_start <<
    // std::dec
    //           << " to 0x" << std::hex << region_simulation.addr_end <<
    //           std::dec
    //           << std::endl;
    return false;
  }

  // Insert new region mapping and enumerate 1:1 address mappings
  regions_.insert({region_process, region_simulation});
  enumerate_region(region_process, region_simulation, true);

  // std::cout << "0x" << std::hex << region_simulation.addr_start << std::dec
  //           << ":0x" << std::hex << region_simulation.addr_end << std::dec
  //           << std::endl;
  return true;
}

bool Translator::update_mapping(memoryRegion region_original,
                                memoryRegion region_process,
                                memoryRegion region_simulation) {
  if (disableTranslation_) return true;
  // std::cout << "# Update mapping:\n 0x" << std::hex
  //           << region_original.addr_start << std::dec << ":0x" << std::hex
  //           << region_original.addr_end << std::dec << "("
  //           << (region_original.addr_end - region_original.addr_start)
  //           << ") = 0x" << std::hex << region_process.addr_start << std::dec
  //           << ":0x" << std::hex << region_process.addr_end << std::dec <<
  //           "("
  //           << (region_process.addr_end - region_process.addr_start) << ") ->
  //           ";

  // Ensure provided region boundaries are valid
  if (region_process.addr_start >= region_process.addr_end ||
      region_simulation.addr_start >= region_simulation.addr_end) {
    // std::cout << "invalid region" << std::endl;
    return false;
  }

  // Ensure translated block is the same size as the original
  if ((region_process.addr_end - region_process.addr_start) !=
      (region_simulation.addr_end - region_simulation.addr_start)) {
    // std::cout << "diff size ("
    //           << (region_process.addr_end - region_process.addr_start) << "
    //           vs "
    //           << (region_simulation.addr_end - region_simulation.addr_start)
    //           << ")" << std::endl;
    return false;
  }
  // Ensure old program region exists
  auto res_old = std::find_if(
      regions_.begin(), regions_.end(),
      [&](const std::pair<memoryRegion, memoryRegion>& mem) {
        return (region_original.addr_start == mem.first.addr_start &&
                region_original.addr_end == mem.first.addr_end);
      });
  if (res_old == regions_.end()) {
    // std::cout << "original doesn't exist" << std::endl;
    return false;
  }

  // Temporarily remove region_original to ensure it's not consdiere din the
  // following checks
  std::pair<memoryRegion, memoryRegion> temp = *res_old;
  regions_.erase(res_old);

  // std::cout << "Found entry 0x" << std::hex << temp.first.addr_start <<
  // std::dec
  //           << " to 0x" << std::hex << temp.first.addr_end << std::dec
  //           << " -> ";

  // Ensure new program region shares no boundary with previous process region
  // std::max used to ensure boundaries of 0 don't wrap around to unsigned(-1)
  auto searched_region =
      std::find_if(regions_.begin(), regions_.end(),
                   [&](const std::pair<memoryRegion, memoryRegion>& mem) {
                     return !(region_process.addr_start >
                                  (std::max(mem.first.addr_end, 1ull) - 1) ||
                              (std::max(region_process.addr_end, 1ull) - 1) <
                                  mem.first.addr_start);
                   });

  if (searched_region != regions_.end()) {
    // std::cout << "Overlap:" << std::endl;
    // std::cout << "\t0x" << std::hex << searched_region->first.addr_start
    //           << std::dec << " to 0x" << std::hex
    //           << searched_region->first.addr_end << std::dec << std::endl;
    // std::cout << "\t0x" << std::hex << region_process.addr_start << std::dec
    //           << " to 0x" << std::hex << region_process.addr_end << std::dec
    //           << std::endl;
    // Add region_original back due to failure in above check
    regions_.insert(temp);
    return false;
  }
  // Ensure new simeng region shares no boundary with previous simeng region
  searched_region =
      std::find_if(regions_.begin(), regions_.end(),
                   [&](const std::pair<memoryRegion, memoryRegion>& mem) {
                     return !(region_simulation.addr_start >
                                  (std::max(mem.second.addr_end, 1ull) - 1) ||
                              (std::max(region_simulation.addr_end, 1ull) - 1) <
                                  mem.second.addr_start);
                   });
  if (searched_region != regions_.end()) {
    // std::cout << "Overlap:" << std::endl;
    // std::cout << "\t0x" << std::hex << searched_region->second.addr_start
    //           << std::dec << " to 0x" << std::hex
    //           << searched_region->second.addr_end << std::dec << std::endl;
    // std::cout << "\t0x" << std::hex << region_simulation.addr_start <<
    // std::dec
    //           << " to 0x" << std::hex << region_simulation.addr_end <<
    //           std::dec
    //           << std::endl;
    // Add region_original back due to failure in above check
    regions_.insert(temp);
    return false;
  }

  // Insert new region mapping and enumerate 1:1 address mappings
  regions_.insert({region_process, region_simulation});
  enumerate_region(region_process, region_simulation, true);
  // std::cout << "0x" << std::hex << temp.second.addr_start << std::dec <<
  // ":0x"
  //           << std::hex << temp.second.addr_end << std::dec << "("
  //           << (temp.second.addr_end - temp.second.addr_start) << ") = 0x"
  //           << std::hex << region_simulation.addr_start << std::dec << ":0x"
  //           << std::hex << region_simulation.addr_end << std::dec << "("
  //           << (region_simulation.addr_end - region_simulation.addr_start)
  //           << ")" << std::endl;
  return true;
}

uint64_t Translator::mmap_allocation(size_t length) {
  // std::cout << "Add Allocation (" << length << "):" << std::endl;
  std::shared_ptr<struct heap_allocation> newAlloc(new heap_allocation);
  // Find suitable region to allocate
  memoryRegion previousAllocation = {0, 0};
  // Determine if the new allocation can fit between existing allocations
  for (heap_allocation& alloc : heapAllocations_) {
    if (alloc.next != NULL && (alloc.next->start - alloc.end) >= length) {
      newAlloc->start = alloc.end;
      newAlloc->mapped_region.addr_start = alloc.mapped_region.addr_end;
      // Re-link contiguous allocation to include new allocation
      newAlloc->next = alloc.next;
      alloc.next = newAlloc;
      // std::cout << "\tFound space after 0x" << std::hex << alloc.start
      //           << std::dec << " to 0x" << std::hex << alloc.end << std::dec
      //           << std::endl;
      break;
    }
  }
  // If still not allocated, append allocation to end of list
  if (newAlloc->start == 0) {
    if (heapAllocations_.size()) {
      // Get last contiguous allocation and add newAlloc after it
      for (heap_allocation& alloc : heapAllocations_) {
        if (alloc.next == NULL) {
          newAlloc->start = alloc.end;
          newAlloc->mapped_region.addr_start = alloc.mapped_region.addr_end;
          alloc.next = newAlloc;
          // std::cout << "\tPlaced at end after 0x" << std::hex << alloc.start
          //           << std::dec << " to 0x" << std::hex << alloc.end <<
          //           std::dec
          //           << std::endl;
          break;
        }
      }
    } else {
      // If no allocations exists, allocate to start of the simulation mmap
      // region
      newAlloc->start = mmapStartAddr_.first;
      newAlloc->mapped_region.addr_start = mmapStartAddr_.second;
      // std::cout << "\tPlaced at start" << std::endl;
    }
  }
  // Define end of regions_
  newAlloc->end = newAlloc->start + length;
  newAlloc->mapped_region.addr_end =
      newAlloc->mapped_region.addr_start + length;
  // The end of a mmap allocation must be rounded up to the nearest page size
  uint64_t remainder = (newAlloc->start + length) % pageSize_;
  newAlloc->end += (remainder != 0) ? (pageSize_ - remainder) : 0;
  newAlloc->mapped_region.addr_end +=
      (remainder != 0) ? (pageSize_ - remainder) : 0;
  heapAllocations_.push_back(*newAlloc);
  // std::cout << "\t0x" << std::hex << newAlloc->start << std::dec << " to 0x"
  //           << std::hex << newAlloc->end << std::dec << std::endl;
  // std::cout << "\t0x" << std::hex << newAlloc->mapped_region.addr_start
  //           << std::dec << " to 0x" << std::hex
  //           << newAlloc->mapped_region.addr_end << std::dec << std::endl;

  // Add mapping for new mmap allocation
  add_mapping({newAlloc->start, newAlloc->end}, newAlloc->mapped_region);

  return newAlloc->start;
}

bool Translator::register_allocation(uint64_t addr, size_t length,
                                     memoryRegion region_simulation) {
  // std::cout << "Register Allocation:" << std::endl;

  // Ensure addr and length maps to a process region
  auto searched_region =
      std::find_if(regions_.begin(), regions_.end(),
                   [&](const std::pair<memoryRegion, memoryRegion>& mem) {
                     return (addr == mem.first.addr_start &&
                             addr + length == mem.first.addr_end);
                   });
  if (searched_region == regions_.end()) {
    // std::cout << "\tno matching process region" << std::endl;
    return false;
  }

  // Ensure memory region exists
  searched_region = std::find_if(
      regions_.begin(), regions_.end(),
      [&](const std::pair<memoryRegion, memoryRegion>& mem) {
        return (region_simulation.addr_start == mem.second.addr_start &&
                region_simulation.addr_end == mem.second.addr_end);
      });
  if (searched_region == regions_.end()) {
    // std::cout << "\tno matching simualtion region" << std::endl;
    return false;
  }

  // Create new heap_allocation that represents mmap allocation
  std::shared_ptr<struct heap_allocation> newAlloc(new heap_allocation);
  newAlloc->start = addr;
  newAlloc->end = addr + length;
  newAlloc->mapped_region = region_simulation;

  // Ensure allocation hasn't already been registered
  auto searched_alloc = std::find_if(
      heapAllocations_.begin(), heapAllocations_.end(),
      [newAlloc](const heap_allocation& alloc) {
        return (newAlloc->start == alloc.start && newAlloc->end == alloc.end);
      });

  if (searched_alloc != heapAllocations_.end()) {
    // std::cout << "\tallocation already registered" << std::endl;
    return false;
  }

  // Ensure memory region hasn't already been assigned
  searched_alloc =
      std::find_if(heapAllocations_.begin(), heapAllocations_.end(),
                   [newAlloc](const heap_allocation& alloc) {
                     return (newAlloc->mapped_region.addr_start ==
                                 alloc.mapped_region.addr_start &&
                             newAlloc->mapped_region.addr_end ==
                                 alloc.mapped_region.addr_end);
                   });

  if (searched_alloc != heapAllocations_.end()) {
    // std::cout << "\tmemory region already assigned" << std::endl;
    return false;
  }

  // Find where prior allocation would fit in current heapAllocations_
  for (heap_allocation& alloc : heapAllocations_) {
    if (alloc.start <= addr && alloc.next == NULL) {
      newAlloc->next = alloc.next;
      alloc.next = newAlloc;
      // std::cout << "\tPlaced after 0x" << std::hex << alloc.start << std::dec
      //           << " to 0x" << std::hex << alloc.end << std::dec <<
      //           std::endl;
      break;
    }
  }
  heapAllocations_.push_back(*newAlloc);
  // std::cout << "\t0x" << std::hex << newAlloc->start << std::dec << " to 0x"
  //           << std::hex << newAlloc->end << std::dec << std::endl;
  // std::cout << "\t0x" << std::hex << newAlloc->mapped_region.addr_start
  //           << std::dec << " to 0x" << std::hex
  //           << newAlloc->mapped_region.addr_end << std::dec << std::endl;
  return true;
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
      // Erase mmap allocation
      heapAllocations_.erase(heapAllocations_.begin() + i);
      if (!disableTranslation_) {
        // Ensure program region exists in mappings_
        auto res_old = std::find_if(
            regions_.begin(), regions_.end(),
            [&](const std::pair<memoryRegion, memoryRegion>& mem) {
              return (alloc.mapped_region.addr_start == mem.second.addr_start &&
                      alloc.mapped_region.addr_end == mem.second.addr_end);
            });
        if (res_old == regions_.end()) {
          return -1;
        }
        // Erase mapping entries
        regions_.erase(res_old->first);
        enumerate_region(res_old->first, res_old->second, false);
      }
      return 0;
    }
  }
  // Not an error if the indicated range does no contain any mapped pages
  return 0;
}

void Translator::setInitialMmapRegion(uint64_t processAddress,
                                      uint64_t simulationAddress) {
  mmapStartAddr_ = {processAddress, simulationAddress};
}

void Translator::setPageSize(uint64_t pagesize) { pageSize_ = pagesize; }

void Translator::disable_translation() { disableTranslation_ = true; }

}  // namespace simeng
