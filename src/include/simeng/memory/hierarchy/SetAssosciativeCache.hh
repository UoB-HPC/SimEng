#include <cstdint>
#include <list>
#include <map>
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
#include "simeng/memory/hierarchy/RequestConvertor.hh"
#include "simeng/memory/hierarchy/TagSchemes.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

/** This class represents a SetAssosciativeCache. */
template <CacheLevel cache_level>
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

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> initCpuPort() override;

  /** Function used to initialise port used to communicate memory requests to a
   * higher level of memory or CPU. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> initTopPort() override;

  /** Function used to initialise port used to communicate memory requests to a
   * lower level of memory. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> initBottomPort() override;

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
  std::queue<CacheLatencyPacket<MemoryHierarchyPacket>> waitQueue_;

  /** Queue used to apply access latency and process memory request which hit
   * the cache. */
  std::queue<CacheLatencyPacket<MemoryHierarchyPacket>> hitQueue_;

  /** Queue which contains requests to be send to a higher level of memory. */
  std::queue<CacheLatencyPacket<MemoryHierarchyPacket>> queueToTopLevel_;

  /** If cache is L1 this queue is used instead to queueToTopLevel to send back
   * CPUMemoryPackets. */
  std::queue<CacheLatencyPacket<CPUMemoryPacket>> queueToCpu_;

  /** Queue which contains requests to be sent to a lower level of memory. */
  std::queue<CacheLatencyPacket<MemoryHierarchyPacket>> queueToLowerLevel_;

  /** Queue which contains all memory requests of type
   * MshrEntry::Type::Secondary. */
  std::queue<CacheLatencyPacket<MemoryHierarchyPacket>> mshrSecondaryQueue_;

  /** Queue which contains all memory requests of which cause a primary miss on
   * a cache line. */
  std::list<CacheLatencyPacket<MemoryHierarchyPacket>> mshrPrimaryReqs_;

  /***/
  std::map<uint64_t, CPUMemoryPacket> reqMap_;

  /** Instantiation of Mshr class. */
  Mshr mshr_;

  /** All cache line in a set assosciate cache. */
  std::vector<UnSectoredCacheLine> cacheLines_;

  /** Instantiation of the replacement policy. */
  LRU replacementPolicy_;

  /** Total number of sets the cache is divided into given assosciativity,
   * cache size and cache line width. */
  uint32_t numSets_;

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> cpuPort_;

  /** Port towards the top-level cache in hierarchy. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> topPort_;

  /** Port towards the low-level cache in heirarchy. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> bottomPort_;

  /** Unique pointer to TagScheme. */
  std::unique_ptr<TagScheme> tagScheme_ = nullptr;

  /***/
  CacheLevel level_ = cache_level;

  /***/
  RequestConvertor convertor_;

  /** Function which allows access to cache. */
  void accessCache(MemoryHierarchyPacket& pkt);

  /** Function which checks if a MemPacket hits a cache line inside the cache.
   */
  AccessInfo checkHit(MemoryHierarchyPacket& pkt);

  /** Function used to read from a cache line. */
  template <CacheLevel TValue>
  void doRead(MemoryHierarchyPacket& req, uint16_t clineIdx);

  /** Function used to write to a cache line. */
  void doWrite(MemoryHierarchyPacket& req, uint16_t clineIdx);

  /** Function used to handle response from the bottom port i.e from lower level
   * of memory.*/
  void handleResponseFromBottomPort(MemoryHierarchyPacket& pkt);
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
