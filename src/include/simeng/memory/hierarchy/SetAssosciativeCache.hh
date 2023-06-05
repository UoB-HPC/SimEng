#include <cstdint>
#include <forward_list>
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

class BaseSetAssosciativeCache : public Cache {
 public:
  BaseSetAssosciativeCache(uint16_t clw, uint8_t assosciativity,
                           uint32_t cacheSize, CacheLatencyInfo latencyInfo,
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
  virtual std::shared_ptr<Port<CPUMemoryPacket>> initCpuPort() override = 0;

  /** Function used to initialise port used to communicate memory requests to
   * a higher level of memory or CPU. */
  virtual std::shared_ptr<Port<MemoryHierarchyPacket>> initTopPort()
      override = 0;

  /** Function used to initialise port used to communicate memory requests to
   * a lower level of memory. */
  virtual std::shared_ptr<Port<MemoryHierarchyPacket>> initBottomPort()
      override = 0;

  /** Function used to invalidate all cache lines in a cache. */
  void invalidateAll() override;

  /** Function used to tick the cache. */
  virtual void tick() override = 0;

  /** Function used to get the Miss status handling register of a cache. */
  Mshr& getMshr() override { return mshr_; }

  /** Function used to return the size of a cache. */
  uint32_t getSize() override { return cacheSize_; }

  /** This variable store the number of ticks. */
  uint64_t ticks_ = 0;

  /** Instantiation of the RequestBuffer. */
  RequestBuffer requestBuffer_;

  /** Queue used to apply hit latency to all incoming memory requests. */
  std::queue<CacheLatencyPacket<MemoryHierarchyPacket>> waitQueue_;

  /** Queue which contains requests to be sent to a lower level of memory. */
  std::queue<CacheLatencyPacket<MemoryHierarchyPacket>> queueToLowerLevel_;

  /** List which contains all memory requests of type for which we can
   * generate an response. */
  std::list<CacheLatencyPacket<MemoryHierarchyPacket>> processBuffer_;

  /** Queue which contains all memory requests of which cause a primary miss
   * on a cache line. */
  std::list<CacheLatencyPacket<MemoryHierarchyPacket>> mshrPrimaryReqs_;

  /** Instantiation of Mshr class. */
  Mshr mshr_;

  /** All cache line in a set assosciate cache. */
  std::vector<UnSectoredCacheLine> cacheLines_;

  /** Instantiation of the replacement policy. */
  LRU replacementPolicy_;

  /** Total number of sets the cache is divided into given assosciativity,
   * cache size and cache line width. */
  uint32_t numSets_;

  /** Port towards the low-level cache in heirarchy. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> bottomPort_;

  /** Unique pointer to TagScheme. */
  std::unique_ptr<TagScheme> tagScheme_ = nullptr;

  /** Function which checks if a MemPacket hits a cache line inside the cache.
   */
  AccessInfo checkHit(MemoryHierarchyPacket& pkt);

  /** Function used to handle response from the bottom port i.e from lower
   * level of memory.*/
  virtual void handleResponseFromBottomPort(MemoryHierarchyPacket& pkt) = 0;
};

/** This class represents a SetAssosciativeCache. */
template <CacheLevel cache_level>
class SetAssosciativeCache;

template <>
class SetAssosciativeCache<CacheLevel::L1> : public BaseSetAssosciativeCache {
 public:
  SetAssosciativeCache<CacheLevel::L1>(uint16_t clw, uint8_t assosciativity,
                                       uint32_t cacheSize,
                                       CacheLatencyInfo latencyInfo,
                                       std::unique_ptr<TagScheme> tagScheme)
      : BaseSetAssosciativeCache(clw, assosciativity, cacheSize, latencyInfo,
                                 std::move(tagScheme)) {}
  /** If cache is L1 this queue is used instead to queueToTopLevel to send
   * back CPUMemoryPackets. */
  std::queue<CPUMemoryPacket> queueToCpu_;

  /***/
  std::map<uint64_t, CPUMemoryPacket> reqMap_;

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> cpuPort_;

  /***/
  void tick() override;

  /** Function used to read from a cache line. */
  CPUMemoryPacket doRead(MemoryHierarchyPacket& req, uint16_t clineIdx);

  /** Function used to write to a cache line. */
  CPUMemoryPacket doWrite(MemoryHierarchyPacket& req, uint16_t clineIdx);

  /** Function used to handle response from the bottom port i.e from lower
   * level of memory.*/
  void handleResponseFromBottomPort(MemoryHierarchyPacket& pkt) override;

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> initCpuPort() override;

  /** Function used to initialise port used to communicate memory requests to
   * a higher level of memory or CPU. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> initTopPort() override;

  /** Function used to initialise port used to communicate memory requests to
   * a lower level of memory. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> initBottomPort() override;
};

template <>
class SetAssosciativeCache<CacheLevel::LL> : public BaseSetAssosciativeCache {
 public:
  /** Port towards the top-level cache in hierarchy. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> topPort_;

  /** Queue which contains requests to be send to a higher level of memory. */
  std::queue<CacheLatencyPacket<MemoryHierarchyPacket>> queueToTopLevel_;

  /***/
  void tick() override;

  /** Function used to read from a cache line. */
  void doRead(MemoryHierarchyPacket& req, uint16_t clineIdx);

  /** Function used to write to a cache line. */
  void doWrite(MemoryHierarchyPacket& req, uint16_t clineIdx);

  /** Function used to handle response from the bottom port i.e from lower
   * level of memory.*/
  void handleResponseFromBottomPort(MemoryHierarchyPacket& pkt) override;

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> initCpuPort() override;

  /** Function used to initialise port used to communicate memory requests to
   * a higher level of memory or CPU. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> initTopPort() override;

  /** Function used to initialise port used to communicate memory requests to
   * a lower level of memory. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> initBottomPort() override;
};

/**
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
*/

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
