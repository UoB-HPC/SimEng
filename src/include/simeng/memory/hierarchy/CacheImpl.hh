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

struct AccessInfo {
  bool valid = false;
  bool dirty = false;
  bool hit = false;
  uint16_t lineIdx = 0;
  uint64_t tag = 0;
  uint16_t byteOffset = 0;
};

class CacheImpl {
 public:
  CacheImpl(uint16_t clw, uint8_t assosciativity, uint32_t cacheSize,
            uint16_t missPenalty)
      : clw_(clw),
        assosciativity_(assosciativity),
        cacheSize_(cacheSize),
        missPenalty_(missPenalty){};

  virtual std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initTopPort() = 0;
  virtual std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
  initBottomPort() = 0;
  virtual void invalidateAll() = 0;

 protected:
  /** Width of the cache line/block. */
  uint16_t clw_;
  /** Assosciativity of the cache line. */
  uint8_t assosciativity_;
  /** Size of the cache. */
  uint32_t cacheSize_;
  /** Miss penalty in terms of clock cycles. */
  uint16_t missPenalty_;
  /** Mask used to calculate the tag from a physical address. */
  uint32_t tagMask_;
};

}  // namespace simeng::memory::hierarchy
