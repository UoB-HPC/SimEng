
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace simeng {
namespace memory {
namespace hierarchy {

/** The ReplacementPolicy abstract class represents the replacement policy a
 * cache uses. This abstract class defines the API which all concrete
 * implementations of replacement policies in SimEng should conform to. */
class ReplacementPolicy {
 public:
  /** Function which is used to find a replacement cache line. */
  virtual uint16_t findReplacement(uint32_t setNum) = 0;

  /** Function which is used to update the usage of a cache line. */
  virtual void updateUsage(uint32_t set, uint16_t line) = 0;

  /** Function used to serialise information regarding cache line usage. This is
   * mainly used for testing purposes. */
  virtual std::string serialiseSet(uint32_t setNum) = 0;
};

class LRU : public ReplacementPolicy {
 public:
  /** The LRUInfo struct stores information related to a cache important for the
   * LRU replacement policy. */
  struct LRUInfo {
    /** This variable stores the index of the cache line in a set. */
    uint16_t lineIndexInSet = 0;
    /** This variable stores the validity of a cache line. */
    bool valid = 0;
  };

  /** Empty constructor for the LRU replacement policy. */
  LRU();

  /** Constructor for the LRU replacement policy. It takes in as arguments the
   * total number of cache lines and the assosciativity of the cache. */
  LRU(uint32_t numBlocks, uint16_t assosciativity);

  /** Function which is used to find a replacement cache line for a particular
   * set. */
  uint16_t findReplacement(uint32_t setNum) override;

  /** Function which is used to update the usage of a cache line in a cache line
   * set. */
  void updateUsage(uint32_t setNum, uint16_t line) override;

  /** Function used to serialise information regarding cache line usage in a
     particular set. This is mainly used for testing purposes. */
  std::string serialiseSet(uint32_t setNum) override;

 private:
  /** Assosciativity of a cache line. */
  uint16_t assosciativity_;

  /** List which stores the LRUInfo structs for all cache lines in all sets. */
  std::vector<LRUInfo> list_;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
