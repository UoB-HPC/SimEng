#include <cstdint>
namespace simeng {
namespace memory {
namespace hierarchy {

struct CacheConfig {
  const uint32_t cacheSize;
  const uint16_t clw;
  const uint16_t assosciativity;
  const uint32_t numRows;
  const uint32_t numCacheLines;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
