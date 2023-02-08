#pragma once
#include <functional>
#include <memory>

#include "simeng/memory/Mem.hh"

typedef std::function<uint64_t(uint64_t, uint64_t)> VAddrTranslator;

namespace simeng {
namespace memory {

/** The MMU class acts as a buffer class defines virtual memory interaction
 * between (Core) and Memory. It can also invoke the OS for virtual memory
 * related tasks i.e Page faults  */
class MMU {
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

  ReadResponse dataAbortReadRes = ReadResponse{~(uint64_t)0, 0};
  WriteResponse dataAbortWriteRes = WriteResponse{~(uint64_t)0, 0};

 public:
  MMU(
      std::shared_ptr<Mem> memory,
      VAddrTranslator fn = [](uint64_t addr, uint64_t pid) -> uint64_t {
        return addr;
      },
      uint64_t pid = 0);
  /** Method used to buffer request from memory interface to memory. */
  void bufferRequest(ReadRequest request,
                     std::function<void(ReadResponse res)> callback);
  void bufferRequest(WriteRequest request,
                     std::function<void(WriteResponse res)> callback);

  /** Method to set PID for the MMU. */
  void setPid(uint64_t pid);
};

}  // namespace memory
}  // namespace simeng
