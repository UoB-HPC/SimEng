#include "simeng/memory/hierarchy/Replacement.hh"

using namespace simeng::memory::hierarchy;

LRU::LRU() : assosciativity_(0) {}

LRU::LRU(uint32_t numBlocks, uint16_t assosciativity)
    : assosciativity_(assosciativity) {
  list_ = std::vector<LRUInfo>(numBlocks);
  for (uint32_t x = 0; x < numBlocks; x++) {
    uint16_t lineNum = x % assosciativity;
    list_[x].lineIndexInSet = lineNum;
  }
}

uint16_t LRU::findReplacement(uint32_t setNum) {
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

void LRU::updateUsage(uint32_t setNum, uint16_t line) {
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

std::string LRU::serialiseSet(uint32_t setNum) {
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
