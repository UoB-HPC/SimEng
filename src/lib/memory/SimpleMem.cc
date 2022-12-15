#include "simeng/memory/SimpleMem.hh"

namespace simeng {
namespace memory {
SimpleMem::SimpleMem(size_t size) {
  memory_ = std::make_shared<char*>(new char[size]);
  memSize_ = size;
}

SimpleMem::~SimpleMem(){};

std::shared_ptr<char*> SimpleMem::getMemory() {
  return std::shared_ptr<char*>(memory_);
};
size_t SimpleMem::getMemorySize() { return memSize_; }

}  // namespace memory
}  // namespace simeng