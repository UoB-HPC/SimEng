#include "simeng/memory/hierarchy/SetAssosciativeCache.hh"

#include <cstdint>
#include <memory>

#include "simeng/memory/MemPacket.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
SetAssosciativeCache::initTopPort() {
  topPort_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> pkt) { accessCache(pkt); };
  topPort_->registerReceiver(fn);
  return topPort_;
}

std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
SetAssosciativeCache::initBottomPort() {
  bottomPort_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  return bottomPort_;
}

void SetAssosciativeCache::invalidateAll() {
  for (auto& cacheLine : sets_) {
    cacheLine.setInvalid();
  }
}

void SetAssosciativeCache::accessCache(std::unique_ptr<MemPacket>& pkt) {
  AccessInfo ainfo = checkHit(pkt);
}

AccessInfo SetAssosciativeCache::checkHit(std::unique_ptr<MemPacket>& pkt) {
  uint16_t setIndex = tagScheme_->calcSetIndex(pkt);
  uint64_t tag = tagScheme_->calcTag(pkt);
  uint16_t startIdx = setIndex * assosciativity_;
  uint16_t endIdx = startIdx + assosciativity_;
  for (uint16_t x = startIdx; x < endIdx; x++) {
    CacheLine& cline = sets_[x];
    if (cline.getTag() == tag) {
      uint16_t byteOffset = tagScheme_->calcByteOffset(pkt);
      return AccessInfo{cline.isValid(), cline.isDirty(), true, x, tag,
                        byteOffset};
    }
  }
  return AccessInfo{};
}

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
