#include <memory>

namespace simeng {
namespace memory {
// Mem interface this will be improved in the future.
class Mem {
 public:
  virtual ~Mem() = default;
  virtual std::shared_ptr<char[]> getMemory() = 0;
  virtual size_t getMemorySize() = 0;
};

}  // namespace memory
}  // namespace simeng