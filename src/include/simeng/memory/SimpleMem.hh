#pragma once
#include <stdint.h>

#include <cstddef>
#include <memory>

#include "simeng/memory/Mem.hh"

namespace simeng {
namespace memory {

// Simple memory class this will be replaced by more complex memory models in
// the future.
class SimpleMem : public Mem {
 public:
  SimpleMem(size_t bytes);
  virtual ~SimpleMem() override;
  std::shared_ptr<char*> getMemory() override;
  size_t getMemorySize() override;

 private:
  std::shared_ptr<char*> memory_;
  size_t memSize_;
};

}  // namespace memory
}  // namespace simeng