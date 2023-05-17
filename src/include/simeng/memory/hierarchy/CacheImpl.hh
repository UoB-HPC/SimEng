#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <queue>
#include <vector>

#include "simeng/Port.hh"
#include "simeng/memory/FixedLatencyMemory.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/hierarchy/RequestBuffer.hh"
#include "simeng/util/Math.hh"

namespace simeng::memory::hierarchy {

class Mshr;

struct AccessInfo {
  bool valid = false;
  bool dirty = false;
  bool hit = false;
  uint16_t lineIdx = 0;
  uint64_t tag = 0;
};

struct CacheLatencyPacket {
  RequestBufferIndex reqBufIdx = -1;
  uint64_t endLatency = 0;
  CacheLatencyPacket(RequestBufferIndex idx, uint64_t endLat)
      : reqBufIdx(idx), endLatency(endLat) {}
};

struct CacheLatencyInfo {
  uint16_t hitLatency = 0;
  uint16_t accessLatency = 0;
  uint16_t missPenalty = 0;
  CacheLatencyInfo(uint16_t hitLtncy, uint16_t accessLtncy, uint16_t missPnlty)
      : hitLatency(hitLtncy),
        accessLatency(accessLtncy),
        missPenalty(missPnlty) {}
  CacheLatencyInfo() {}
};

class Cache {
 public:
  Cache(uint16_t clw, uint8_t assosciativity, uint32_t cacheSize,
        CacheLatencyInfo latencyInfo)
      : clw_(clw),
        assosciativity_(assosciativity),
        cacheSize_(cacheSize),
        latencyInfo_(latencyInfo) {}

  virtual std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initTopPort() = 0;
  virtual std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
  initBottomPort() = 0;

  virtual void invalidateAll() = 0;
  virtual void tick() = 0;
  virtual Mshr& getMshr() = 0;
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
  /***/
  CacheLatencyInfo latencyInfo_;
};

}  // namespace simeng::memory::hierarchy
