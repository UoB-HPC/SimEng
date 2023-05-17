#include <cstdint>
#include <list>
#include <memory>
#include <queue>
#include <vector>

#include "simeng/memory/FixedLatencyMemory.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/hierarchy/CacheImpl.hh"
#include "simeng/memory/hierarchy/CacheLines.hh"
#include "simeng/memory/hierarchy/Mshr.hh"
#include "simeng/memory/hierarchy/Replacement.hh"
#include "simeng/memory/hierarchy/RequestBuffer.hh"
#include "simeng/memory/hierarchy/TagSchemes.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

class SetAssosciativeCache : public Cache {
  using PacketIterator = std::list<std::unique_ptr<MemPacket>>::iterator;

 public:
  SetAssosciativeCache(uint16_t clw, uint8_t assosciativity, uint32_t cacheSize,
                       CacheLatencyInfo latencyInfo,
                       std::unique_ptr<TagScheme> tagScheme)
      : Cache(clw, assosciativity, cacheSize, latencyInfo),
        tagScheme_(std::move(tagScheme)) {
    uint16_t numCacheLines = cacheSize / clw;
    cacheLines_.reserve(numCacheLines);
    for (int x = 0; x < numCacheLines; x++) {
      cacheLines_.push_back(UnSectoredCacheLine(clw));
    }
    replacementPolicy_ = LRU(numCacheLines, assosciativity);
  }

  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initTopPort() override;
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initBottomPort() override;

  void invalidateAll() override;
  void tick() override;

  Mshr& getMshr() override { return mshr_; }

  uint32_t getSize() override { return cacheSize_; }

 private:
  /***/
  uint64_t ticks_ = 0;

  /***/
  RequestBuffer<512> requestBuffer_;

  /***/
  std::queue<CacheLatencyPacket> waitQueue_;

  /***/
  std::queue<CacheLatencyPacket> hitQueue_;

  /***/
  std::queue<CacheLatencyPacket> queueToCpu_;

  /***/
  std::queue<CacheLatencyPacket> queueToMem_;

  /***/
  std::queue<CacheLatencyPacket> mshrSecondaryQueue_;

  /***/
  std::list<CacheLatencyPacket> mshrPrimaryReqs_;

  /***/
  Mshr mshr_;

  /** All cache line in a set assosciate cache. */
  std::vector<UnSectoredCacheLine> cacheLines_;

  std::list<std::unique_ptr<MemPacket>> pkt;

  /***/
  LRU replacementPolicy_;

  /** Total number of sets the cache is divided into given assosciativity,
   * cache size and cache line width. */
  uint32_t numSets_;

  /** Port towards the top-level cache in hierarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> topPort_;

  /** Port towards the low-level cache in heirarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> bottomPort_;

  /** Queue to hold all pending requests. */
  std::queue<CacheLatencyPacket> pendingReqs_;

  /** Queue to hold all request which will handled in the lower level of memory.
   */
  std::queue<CacheLatencyPacket> queueToLowerMem_;

  /** Unique pointer to TagScheme. */
  std::unique_ptr<TagScheme> tagScheme_ = nullptr;

  void accessCache(std::unique_ptr<MemPacket>& pkt);

  AccessInfo checkHit(std::unique_ptr<MemPacket>& pkt);

  void doRead(std::unique_ptr<MemPacket>& req);
  void doWrite(std::unique_ptr<MemPacket>& req);

  void handleResponseFromBottomPort(std::unique_ptr<MemPacket>& pkt);
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
