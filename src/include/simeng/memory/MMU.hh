#pragma once
#include <functional>
#include <memory>

#include "simeng/memory/Mem.hh"

typedef std::function<uint64_t(uint64_t, uint64_t)> VAddrTranslator;

namespace simeng {
namespace memory {

/** The MMU class acts as a buffer class between memory interfaces and memory.
 * It is mainly responsible for invoking virtual address translation mechanisms
 * before the memory request is sent off to main memory. */
class MMU {
 public:
  MMU(std::shared_ptr<Mem> memory, VAddrTranslator fn, uint64_t tid = 0);

  /** Method used to buffer requests from memory interface to memory. */
  void bufferRequest(DataPacket* request,
                     std::function<void(DataPacket*)> sendRespToMemInterface);

  /** Method to set TID for the MMU. */
  void setTid(uint64_t tid);

 private:
  /** Reference to the memory */
  std::shared_ptr<Mem> memory_ = nullptr;

  /** Callback function which invokes the OS for translation on
   * TLB misses. */
  VAddrTranslator translate_;

  /** TID of the process assosciated with this core. */
  uint64_t tid_;
};

}  // namespace memory
}  // namespace simeng
