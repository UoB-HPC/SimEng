#include <cstdint>
#include <memory>
#include <queue>

#include "simeng/memory/FixedLatencyMemory.hh"
#include "simeng/memory/hierarchy/CacheImpl.hh"
#include "simeng/memory/hierarchy/CacheLines.hh"
#include "simeng/memory/hierarchy/TagSchemes.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

class SetAssosciativeCache : public CacheImpl {
 public:
  SetAssosciativeCache(uint16_t clw, uint8_t assosciativity, uint32_t cacheSize,
                       uint16_t missPenalty,
                       std::unique_ptr<TagScheme> tagScheme)
      : CacheImpl(clw, assosciativity, cacheSize, missPenalty),
        tagScheme_(std::move(tagScheme)) {}

  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initTopPort() override;
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initBottomPort() override;
  void invalidateAll() override;

 private:
  /** Miss penalty in terms of clock cycles. */
  uint16_t missPenalty_;

  /** Sets of cache lines/blocks. */
  std::vector<CacheLine> sets_;

  /** Total number of sets the cache is divided into given assosciativity, cache
   * size and cache line width. */
  uint32_t numSets_;

  /** Port towards the top-level cache in hierarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> topPort_;

  /** Port towards the low-level cache in heirarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> bottomPort_;

  /** Queue to hold all pending requests. */
  std::queue<LatencyPacket> pendingReqs_;

  /** Queue to hold all missed requests. */
  std::queue<LatencyPacket> missedReqs_;

  /** Unique pointer to TagScheme. */
  std::unique_ptr<TagScheme> tagScheme_ = nullptr;

  void accessCache(std::unique_ptr<MemPacket>& pkt);

  AccessInfo checkHit(std::unique_ptr<MemPacket>& pkt);
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
