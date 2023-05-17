#pragma once

#include <cstdint>
#include <vector>
namespace simeng {
namespace memory {
namespace hierarchy {

struct CacheInfo {
  uint64_t clineAddr = 0;
  uint64_t basePaddr = 0;
  uint16_t size = 0;
  uint16_t clineIdx = -1;
  bool dirty = false;
  std::vector<char> data;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
