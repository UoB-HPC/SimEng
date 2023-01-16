#pragma once
#include <functional>
#include <memory>

#include "simeng/memory/Mem.hh"

typedef std::function<uint64_t(uint64_t, uint64_t)> VAddrTranslator;

namespace simeng {
namespace memory {

class MMU {
 private:
  std::shared_ptr<Mem> memory_ = nullptr;
  VAddrTranslator translate_;
  uint64_t pid_;

 public:
  MMU(std::shared_ptr<Mem> memory, VAddrTranslator fn, uint64_t pid);
  void bufferRequest(DataPacket* request,
                     std::function<void(DataPacket*)> callback);
  void setTranslator(VAddrTranslator translator);
  void setPid(uint64_t pid);
};

}  // namespace memory
}  // namespace simeng
