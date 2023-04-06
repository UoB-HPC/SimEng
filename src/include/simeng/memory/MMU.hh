#pragma once
#include <functional>
#include <memory>

#include "simeng/Port.hh"
#include "simeng/PubSub.hh"
#include "simeng/memory/MemPacket.hh"

typedef std::function<uint64_t(uint64_t, uint64_t)> VAddrTranslator;

namespace simeng {
namespace memory {

typedef std::function<void(std::unique_ptr<MemPacket> packet)>
    sendResponseToMemInterface;

/** The MMU class acts as a buffer class between memory interfaces and memory.
 * It is mainly responsible for invoking virtual address translation mechanisms
 * before the memory request is sent off to main memory. */
class MMU {
 public:
  MMU(VAddrTranslator fn, uint64_t tid);

  /** Method used to buffer requests from the memory interface to memory. */
  void bufferRequest(std::unique_ptr<MemPacket> request,
                     sendResponseToMemInterface sendResponse);

  /** Method to set the TID for the MMU. */
  void setTid(uint64_t tid);

  Port<std::unique_ptr<MemPacket>>* initPort();

  ~MMU() { delete port_; }

 private:
  /** Callback function which invokes the OS for translation on
   * TLB misses. */
  VAddrTranslator translate_;

  /** TID of the process assosciated with this MMU. */
  uint64_t tid_;

  sendResponseToMemInterface sendResponse_ = nullptr;

  Port<std::unique_ptr<MemPacket>>* port_ = nullptr;
};

}  // namespace memory
}  // namespace simeng
