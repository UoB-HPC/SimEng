#pragma once

#include <algorithm>
#include <unordered_map>
#include <vector>

namespace simeng {

/** A struct for storing a translation. */
struct Translation {
  uint64_t address;
  bool allocation;

  Translation(uint64_t address, bool allocation) {
    this->address = address;
    this->allocation = allocation;
  }

  bool operator==(const Translation& t) const {
    return address == t.address && allocation == t.allocation;
  }
};

/** A struct to hold the bounds of memory region. */
struct memoryRegion {
  uint64_t addr_start;
  uint64_t addr_end;

  memoryRegion(uint64_t addr_start, uint64_t addr_end) {
    this->addr_start = addr_start;
    this->addr_end = addr_end;
  }

  bool operator==(const memoryRegion& r) const {
    return addr_start == r.addr_start && addr_end == r.addr_end;
  }
};

/** Struct to hold information about a heap allocation and it's mapped region in
 * SimEng memory. */
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

// Hash function for memoryRegion keys
struct hash_fn {
  size_t operator()(const memoryRegion& region) const {
    size_t r_start = std::hash<uint64_t>()(region.addr_start);
    size_t r_end = std::hash<uint64_t>()(region.addr_end);

    return r_start ^ r_end;
  }
};

/** A class to translate program addresses to the SimEng memory address space.
 * Additionally provides an implementation of mmap and munmap system calls to
 * the SimEng memory space. */
class Translator {
 public:
  Translator();
  ~Translator();

  /** Get the mapping for the supplied program address. */
  const Translation get_mapping(uint64_t addr) const;

  /** Add the mapping form the supplied process memory region to SimEng
   * memory region. Note, upper bound is non-inclusive. */
  bool add_mapping(memoryRegion region_process, memoryRegion region_simulation);

  /** Update a region with the supplied new mapping between process and
   * SimEng memory regions. Note, upper bound is non-inclusive. */
  bool update_mapping(memoryRegion region_original, memoryRegion region_process,
                      memoryRegion region_simulation);

  /** Invoked by a mmap system call. Add a mmap region of a supplied length to
   * the contiguous list of heapAllocations_. */
  uint64_t mmap_allocation(size_t length);

  /** Register a memory allocation that has preivously been created through a
   * mmap call. */
  bool register_allocation(uint64_t addr, size_t length,
                           memoryRegion region_simulation);

  /** Invoked by a munmap system call. Removed a previously mmap allocation and
   * its memory mapping. */
  int64_t munmap_deallocation(uint64_t addr, size_t length);

  /** Set the initial mmap region address for both process and SimEng memory. */
  void setInitialMmapRegion(uint64_t processAddress,
                            uint64_t simulationAddress);

  /** Set the page size used by the process being simulated. */
  void setPageSize(uint64_t pagesize);

  /** From a process and simulation memory region pair, create a set of 1:1
   * mapping entries in the mappings_ unordered_map. The insert parameters
   * controls whether keys generated from the provided memory regions are
   * inserted or erased from mappings_. */
  void enumerate_region(memoryRegion region_process,
                        memoryRegion region_simulation, bool insert);

  /** Disable the translation of addresses. Note, mmap and munmap specific logic
   * is still invoked. */
  void disable_translation();

 private:
  /** Holds program to SimEng address mappings. */
  std::unordered_map<uint64_t, uint64_t> mappings_;

  /** Holds the memory regions currently mapped. */
  std::unordered_map<memoryRegion, memoryRegion, hash_fn> regions_;

  /** Hold the program and SimEng program breaks respectively. */
  std::pair<uint64_t, uint64_t> mmapStartAddr_ = {0, 0};

  /** A vector holding a contiguous list of mmap allocations. */
  std::vector<heap_allocation> heapAllocations_;

  uint64_t pageSize_ = 4096;
  bool disableTranslation_ = false;
};

}  // namespace simeng
