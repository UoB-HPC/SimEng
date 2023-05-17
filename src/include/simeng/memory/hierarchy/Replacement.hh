
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace simeng {
namespace memory {
namespace hierarchy {

class ReplacementPolicy {
 public:
  virtual uint16_t findReplacement(uint32_t setNum) = 0;
  virtual void updateUsage(uint32_t set, uint16_t line) = 0;
  virtual std::string serialiseSet(uint32_t setNum) = 0;
};

class LRU : public ReplacementPolicy {
 public:
  struct LRUInfo {
    uint16_t lineIndexInSet = 0;
    bool valid = 0;
  };

  LRU() : assosciativity_(0) {}

  LRU(uint32_t numBlocks, uint16_t assosciativity)
      : assosciativity_(assosciativity) {
    list_ = std::vector<LRUInfo>(numBlocks);
    for (uint32_t x = 0; x < numBlocks; x++) {
      uint16_t lineNum = x % assosciativity;
      list_[x].lineIndexInSet = lineNum;
    }
  }

  uint16_t findReplacement(uint32_t setNum) override {
    uint32_t setStartIdx = setNum * assosciativity_;
    uint32_t setEndIdx = setStartIdx + assosciativity_;
    uint32_t listIdx = setStartIdx;
    LRUInfo info = list_[setStartIdx];
    for (; listIdx < setEndIdx - 1; listIdx++) {
      list_[listIdx] = list_[listIdx + 1];
    }
    info.valid = 1;
    list_[listIdx] = info;
    return info.lineIndexInSet;
  };

  void updateUsage(uint32_t setNum, uint16_t line) override {
    uint32_t listIdx = (setNum * assosciativity_);
    uint32_t setEndIdx = (setNum * assosciativity_) + assosciativity_;
    LRUInfo info;
    for (; listIdx < setEndIdx; listIdx++) {
      if (line == list_[listIdx].lineIndexInSet) {
        info = list_[listIdx];
        break;
      }
    }
    for (; listIdx < setEndIdx - 1; listIdx++) {
      list_[listIdx] = list_[listIdx + 1];
    }
    info.valid = 1;
    list_[listIdx] = info;
  }

  std::string serialiseSet(uint32_t setNum) override {
    uint32_t setStartIdx = setNum * assosciativity_;
    uint32_t setEndIdx = setStartIdx + assosciativity_;
    uint32_t listIdx = setStartIdx;
    std::string buff;
    for (; listIdx < setEndIdx - 1; listIdx++) {
      buff += std::to_string(list_[listIdx].lineIndexInSet) + "->";
    }
    buff += std::to_string(list_[listIdx].lineIndexInSet);
    return buff;
  }

  uint16_t assosciativity_;

 private:
  std::vector<LRUInfo> list_;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
