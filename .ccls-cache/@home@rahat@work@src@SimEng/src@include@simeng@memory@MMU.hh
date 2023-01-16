#pragma once
#include <functional>
#include <memory>

#include "simeng/memory/Mem.hh"

typedef std::function<uint64_t(uint64_t, uint64_t)> VAddrTranslator;

namespace simeng {
namespace memory {

/**
 * The MMU class acts as a buffer class between memory interface and memory. It
 * is mainly responsible for invoking virtual address translation mechanisms
 * before the memory request is sent off to main memory.
 */
class MMU {
 public:
  MMU(
      std::shared_ptr<Mem> memory,
      VAddrTranslator fn = [](uint64_t addr, uint64_t pid) -> uint64_t {
        return addr;
      },
      uint64_t pid = 0);

  /** Method used to buffer request from memory interface to memory. */
  void bufferRequest(DataPacket* request,
                     std::function<void(DataPacket*)> callback);

  /** Method to set PID for the MMU. */
  void setPid(uint64_t pid);

 private:
  /** Reference to the memory */
  std::shared_ptr<Mem> memory_ = nullptr;

  /**
   * Reference to callback function which invokes the OS for translation on TLB
   * misses
   */
  VAddrTranslator translate_;

  /** PID of the process assosciated with this core. */
  uint64_t pid_;
};

}  // namespace memory
}  // namespace simeng
