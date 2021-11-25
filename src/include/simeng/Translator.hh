#pragma once

#include <algorithm>
#include <unordered_map>
#include <vector>

namespace simeng {

/** A struct for storing a translation. */
struct Translation {
  uint64_t address;
  bool allocation;
};

/** A struct to hold the bounds of memory region. */
struct memoryRegion {
  uint64_t addr_start;
  uint64_t addr_end;

  bool isStack;

  // constructor
  memoryRegion(uint64_t addr_start, uint64_t addr_end, bool isStack = false) {
    this->addr_start = addr_start;
    this->addr_end = addr_end;
    this->isStack = isStack;
  }

  // `operator==` is required to compare keys in case of a hash collision
  bool operator==(const memoryRegion& p) const {
    return addr_start == p.addr_start && addr_end == p.addr_end;
  }
};

/** Struct to hold information about a heap allocation and it's mapped region in
 * simualtion memory. */
struct heap_allocation {
  /** The address representing the start of the memory allocation. */
  uint64_t start = 0;
  /** The address representing the end of the memory allocation. */
  uint64_t end = 0;
  /** The next allocation. */
  std::shared_ptr<struct heap_allocation> next = NULL;
  /** The mapped region of allocation. */
  memoryRegion mapped_region = {0, 0};
};

// The specialized hash function for `unordered_map` keys
struct hash_fn {
  std::size_t operator()(const memoryRegion& region) const {
    std::size_t h1 = std::hash<uint64_t>()(region.addr_start);
    std::size_t h2 = std::hash<uint64_t>()(region.addr_end);

    return h1 ^ h2;
  }
};

/** A translator for memory addresses. */
class Translator {
 public:
  Translator();
  ~Translator();
  const Translation get_mapping(uint64_t addr) const;
  bool add_mapping(memoryRegion process, memoryRegion b);
  bool update_mapping(memoryRegion a, memoryRegion b, memoryRegion c);

  uint64_t mmap_allocation(size_t length);
  int64_t munmap_deallocation(uint64_t addr, size_t length);

  void setHeapStart(uint64_t processAddress, uint64_t simulationAddress);
  void setPageSize(uint64_t pagesize);

 private:
  std::unordered_map<memoryRegion, memoryRegion, hash_fn> mappings;
  std::pair<uint64_t, uint64_t> heapStarts_ = {0, 0};
  std::vector<heap_allocation> heapAllocations_;
  uint64_t pageSize_ = 4096;
};

}  // namespace simeng
