#pragma once

#include <bitset>
#include <cmath>
#include <cstdint>
#include <memory>

#include "simeng/memory/MemPacket.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

/** The TagScheme class represent the scheme used by a cache to generate tags,
 * set-indeces and byte-offsets from addresses of memory requests. All this
 * information is fundamental for accessing the cache and is used to find cache
 * line correspnding to a memory address as well as to correctly index/locate
 * the data within a cache line. */
class TagScheme {
 public:
  /** Size of the cache. */
  const uint32_t cacheSize_;

  /** Cache line width of the cache. */
  const uint16_t clw_;

  /** Assosciativity of the cache. */
  const uint16_t assosciativity_;

  /** Constructor for the TagScheme abstract class. */
  TagScheme(uint32_t cacheSize, uint16_t clw, uint16_t assosciativity)
      : cacheSize_(cacheSize), clw_(clw), assosciativity_(assosciativity) {}

  /** Function which generates the set index from a MemPacket. */
  virtual inline uint16_t calcSetIndex(std::unique_ptr<MemPacket>& pkt) = 0;

  /** Function which generates  the byte offset from a MemPacket. */
  virtual inline uint16_t calcByteOffset(std::unique_ptr<MemPacket>& pkt) = 0;

  /** Function which generates the tag from a MemPacket. */
  virtual inline uint16_t calcTag(std::unique_ptr<MemPacket>& pkt) = 0;

 protected:
  /** Mask used to extract tag from address contained in the MemPacket. */
  uint64_t tagMask_ = 0;
  /** Mask used to extract byte offset from address contained in the MemPacket.
   */
  uint16_t byteOffsetMask_ = 0;
  /** Mask used to extract set index from address contained in the MemPacket. */
  uint16_t setIndexMask_ = 0;

  /** Function which generate all masks depending on size, cache line width and
   * assosciativity of cache*/
  virtual inline void calcMasks(uint64_t cacheSize, uint16_t clw,
                                uint16_t assosciativity) = 0;
};

/** The PIPT (Physically Indexed Physically Tagged) class represents a tag
 * scheme which uses the physical address to calculate the tag, set index and
 * byte-offset required for accessing the cache. */
class PIPT : public TagScheme {
 public:
  /** Constructor of the PIPT class. */
  PIPT(uint32_t cacheSize, uint16_t clw, uint16_t assosciativity)
      : TagScheme(cacheSize, clw, assosciativity) {
    calcMasks(cacheSize, clw, assosciativity);
  }
  /** Function which calculates the byte offset from the physical address of a
   * MemPacket. */
  inline uint16_t calcByteOffset(std::unique_ptr<MemPacket>& pkt) override {
    return pkt->paddr_ & byteOffsetMask_;
  }
  /** Function which calculates the set index from the physical address of a
   * MemPacket. */
  inline uint16_t calcSetIndex(std::unique_ptr<MemPacket>& pkt) override {
    return ((pkt->paddr_ & setIndexMask_) >> setIndexMaskShift_);
  }
  /** Function which calculates the tag from the physical address of a
   * MemPacket. */
  inline uint16_t calcTag(std::unique_ptr<MemPacket>& pkt) override {
    return ((pkt->paddr_ & tagMask_) >> tagMaskShift_);
  }

 private:
  uint8_t tagMaskShift_ = 0;
  uint8_t setIndexMaskShift_ = 0;

  /** Function which generate all masks depending on size, cache line width and
   * assosciativity of cache*/
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
