#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <queue>
#include <vector>

#include "simeng/Port.hh"
#include "simeng/memory/FixedLatencyMemory.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/util/Math.hh"

namespace simeng::memory::hierarchy {

class Mshr;

enum class CacheLevel : uint8_t { L1, LL };

/** The AccessInfo struct is used store information regarding initial cache
 * access i.e when it is determined whether a request hits or misses. */
struct AccessInfo {
  bool valid = false;
  bool dirty = false;
  bool hit = false;
  uint16_t lineIdx = 0;
};

/** The CacheLatencyPacket struct holds the latency (in terms of clock cycles)
 * to be applied on the memory request. This struct holds the RequestBufferIndex
 * of the memory request in question. */
template <class T>
struct CacheLatencyPacket {
  /***/
  T payload;
  /** Clock cycle at which the memory request can be processed. endLatency of 0
   * signifies immediate processing. */
  uint64_t endLatency = 0;
  /** This is the index of cache line which is evicted or fetched. */
  uint16_t clineIdx = -1;

  /** Constructor for CacheLatencyPacket. */
  CacheLatencyPacket(T value, uint64_t endLat)
      : endLatency(endLat), clineIdx(-1) {
    if constexpr (is_unique_ptr<T>::value) {
      payload = std::move(value);
    } else {
      payload = value;
    }
  }
  /** Constructor for CacheLatencyPacket. */
  CacheLatencyPacket(T value, uint64_t endLat, uint64_t cacheLineIdx)
      : endLatency(endLat), clineIdx(cacheLineIdx) {
    if constexpr (is_unique_ptr<T>::value) {
      payload = std::move(value);
    } else {
      payload = value;
    }
  }
};

/** The CacheLatencyInfo struct holds values for all latencies to be applied on
 * memory requests being processed by a cache hierarchy. */
struct CacheLatencyInfo {
  /** Hit latency signifies the latency it takes to determine whether a memory
   * requests hits or misses the cache. */
  uint16_t hitLatency = 0;
  /** Access latency signifies the latency it takes to access the cache after it
   * hits the cache. */
  uint16_t accessLatency = 0;
  /** Miss penalty signifies the latency it takes to pass the memory request to
   * a lower level of cache. */
  uint16_t missPenalty = 0;
  /** Constructor for the CacheLatencyInfo struct. */
  CacheLatencyInfo(uint16_t hitLtncy, uint16_t accessLtncy, uint16_t missPnlty)
      : hitLatency(hitLtncy),
        accessLatency(accessLtncy),
        missPenalty(missPnlty) {}
  /** Empty constructor for the CacheLatencyInfo struct. */
  CacheLatencyInfo() {}
};

/** The Cache abstract class represent a cache in the memory hierarchy, and is
 * used to model different kinds of cache. A caches must inherit this class. */
class Cache {
 public:
  /** Constructor for the Cache abstract class. */
  Cache(uint16_t clw, uint8_t assosciativity, uint32_t cacheSize,
        CacheLatencyInfo latencyInfo)
      : clw_(clw),
        assosciativity_(assosciativity),
        cacheSize_(cacheSize),
        latencyInfo_(latencyInfo) {}

  /***/
  virtual std::shared_ptr<Port<CPUMemoryPacket>> initCpuPort() = 0;

  /** Function used to initialise port used to communicate memory requests to a
   * higher level of memory or CPU. */
  virtual std::shared_ptr<Port<MemoryHierarchyPacket>> initTopPort() = 0;

  /** Function used to initialise port used to communicate memory requests to a
   * lower level of memory. */
  virtual std::shared_ptr<Port<MemoryHierarchyPacket>> initBottomPort() = 0;

  /** Function used to invalidate all cache lines in a cache. */
  virtual void invalidateAll() = 0;

  /** Function used to tick the cache. */
  virtual void tick() = 0;

  /** Function used to get the Miss status handling register of a cache. */
  virtual Mshr& getMshr() = 0;

  /** Function used to return the size of a cache. */
  virtual uint32_t getSize() = 0;

 protected:
  /** Width of the cache line/block. */
  uint16_t clw_;
  /** Assosciativity of the cache line. */
  uint8_t assosciativity_;
  /** Size of the cache. */
  uint32_t cacheSize_;
  /** Mask used to calculate the tag from a physical address. */
  uint32_t tagMask_;
  /** Instantiation of the CacheLatencyInfo struct. */
  CacheLatencyInfo latencyInfo_;
};

}  // namespace simeng::memory::hierarchy
