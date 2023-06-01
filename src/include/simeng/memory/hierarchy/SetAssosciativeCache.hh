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

/** This class represents a SetAssosciativeCache. */
class SetAssosciativeCache : public Cache {
 public:
  /** Constructor of the SetAssosciativeCache. */
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
  /** Function used to initialise port used to communicate memory requests to a
   * higher level of memory or CPU. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initTopPort() override;

  /** Function used to initialise port used to communicate memory requests to a
   * lower level of memory. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initBottomPort() override;

  /** Function used to invalidate all cache lines in a cache. */
  void invalidateAll() override;

  /** Function used to tick the cache. */
  void tick() override;

  /** Function used to get the Miss status handling register of a cache. */
  Mshr& getMshr() override { return mshr_; }

  /** Function used to return the size of a cache. */
  uint32_t getSize() override { return cacheSize_; }

 private:
  /** This variable store the number of ticks. */
  uint64_t ticks_ = 0;

  /** Instantiation of the RequestBuffer. */
  RequestBuffer requestBuffer_;

  /** Queue used to apply hit latency to all incoming memory requests. */
  std::queue<CacheLatencyPacket> waitQueue_;

  /** Queue used to apply access latency and process memory request which hit
   * the cache. */
  std::queue<CacheLatencyPacket> hitQueue_;

  /** Queue which contains requests to be send to a higher level of memory. */
  std::queue<CacheLatencyPacket> queueToTopLevel_;

  /** Queue which contains requests to be sent to a lower level of memory. */
  std::queue<CacheLatencyPacket> queueToLowerLevel_;

  /** Queue which contains all memory requests of type
   * MshrEntry::Type::Secondary. */
  std::queue<CacheLatencyPacket> mshrSecondaryQueue_;

  /** Queue which contains all memory requests of which cause a primary miss on
   * a cache line. */
  std::list<CacheLatencyPacket> mshrPrimaryReqs_;

  /** Instantiation of Mshr class. */
  Mshr mshr_;

  /** All cache line in a set assosciate cache. */
  std::vector<UnSectoredCacheLine> cacheLines_;

  /** Instantiation of the replacement policy. */
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

  /** Unique pointer to TagScheme. */
  std::unique_ptr<TagScheme> tagScheme_ = nullptr;

  /** Function which allows access to cache. */
  void accessCache(std::unique_ptr<MemPacket>& pkt);

  /** Function which checks if a MemPacket hits a cache line inside the cache.
   */
  AccessInfo checkHit(std::unique_ptr<MemPacket>& pkt);

  /** Function used to read from a cache line. */
  void doRead(std::unique_ptr<MemPacket>& req, uint16_t clineIdx);

  /** Function used to write to a cache line. */
  void doWrite(std::unique_ptr<MemPacket>& req, uint16_t clineIdx);

  /** Function used to handle response from the bottom port i.e from lower level
   * of memory.*/
  void handleResponseFromBottomPort(std::unique_ptr<MemPacket>& pkt);
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
