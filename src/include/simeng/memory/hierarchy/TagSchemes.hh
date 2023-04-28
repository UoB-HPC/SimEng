#include <cmath>
#include <cstdint>
#include <memory>

#include "simeng/memory/MemPacket.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

class TagScheme {
 public:
  const uint32_t cacheSize_;
  const uint16_t clw_;
  const uint16_t assosciativity_;
  TagScheme(uint32_t cacheSize, uint16_t clw, uint16_t assosciativity)
      : cacheSize_(cacheSize), clw_(clw), assosciativity_(assosciativity) {}
  virtual inline uint16_t calcSetIndex(std::unique_ptr<MemPacket>& pkt) = 0;
  virtual inline uint16_t calcByteOffset(std::unique_ptr<MemPacket>& pkt) = 0;
  virtual inline uint16_t calcTag(std::unique_ptr<MemPacket>& pkt) = 0;

 protected:
  uint64_t tagMask_ = 0;
  uint16_t byteOffsetMask_ = 0;
  uint16_t setIndexMask_ = 0;
  uint8_t tagMaskShift_ = 0;
  uint8_t setIndexMaskShift_ = 0;
  virtual inline void calcMasks(uint64_t cacheSize, uint16_t clw,
                                uint16_t assosciativity) = 0;
};

class PIPT : public TagScheme {
 public:
  PIPT(uint32_t cacheSize, uint16_t clw, uint16_t assosciativity)
      : TagScheme(cacheSize, clw, assosciativity) {}

  inline uint16_t calcByteOffset(std::unique_ptr<MemPacket>& pkt) override {
    return pkt->paddr_ & byteOffsetMask_;
  }

  inline uint16_t calcSetIndex(std::unique_ptr<MemPacket>& pkt) override {
    return ((pkt->paddr_ & setIndexMask_) >> setIndexMaskShift_);
  }

  inline uint16_t calcTag(std::unique_ptr<MemPacket>& pkt) override {
    return ((pkt->paddr_ & tagMask_) >> tagMaskShift_);
  }

 private:
  inline void calcMasks(uint64_t cacheSize, uint16_t clw,
                        uint16_t assosciativity) override {
    byteOffsetMask_ = clw - 1;
    uint8_t byteOffsetMaskHw = std::log2(upAlign(byteOffsetMask_, 2));

    setIndexMask_ = calcSetIndexMask(cacheSize, clw, assosciativity);
    uint8_t setIndexMaskHw = std::log2(upAlign(setIndexMask_, 2));

    setIndexMask_ = setIndexMask_ << byteOffsetMaskHw;

    setIndexMaskShift_ = byteOffsetMaskHw;
    tagMaskShift_ = setIndexMaskShift_ + setIndexMaskHw;

    tagMask_ = ~tagMask_;
    tagMask_ = tagMask_ << tagMaskShift_;
  };

  inline uint16_t calcSetIndexMask(uint64_t cacheSize, uint16_t clw,
                                   uint16_t assosciativity) {
    uint32_t rowSize = assosciativity * clw;
    uint32_t numRows = cacheSize / rowSize;
    return upAlign(numRows, 2) - 1;
  }
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
