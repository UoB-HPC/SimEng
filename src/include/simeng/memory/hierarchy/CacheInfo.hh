#pragma once

#include <cstdint>
#include <vector>
namespace simeng {
namespace memory {
namespace hierarchy {

/** The CacheInfo struct is used  by simeng::memory::MemPacket class to hold
 * information used to process the memory request in a lower level of memory
 * incase of a cache miss. It holds information related to fetching or evicting
 * a cache line. */
struct CacheInfo {
  /** clineAddr represents the starting physical address of data cached in a
   * cache line/cache block. clineAddr is only used during evictions of dirty
   * cache lines due to replacement. This is because during an eviction we need
   * to know physical address where the data has to be written. */
  uint64_t clineAddr = 0;
  /** The basePaddr represent the physical address from where we need fetch data
   * from the lower level of memory. basePaddr is used during primary fetches or
   * replacements to non-dirty cache lines. */
  uint64_t basePaddr = 0;
  /** size is an alias of cache line width. */
  uint16_t size = 0;
  /** This is the index of cache line which is evicted or fetched. */
  uint16_t clineIdx = -1;
  /** This signifies if the cache line is dirty. */
  bool dirty = false;
  /** This vector carries the data of cache line being evicted. It is empty
   * incase a cache line is only being fetched. */
  std::vector<char> data;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
