#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <queue>

#include "simeng/OS/Constants.hh"
#include "simeng/Port.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/MemRequests.hh"
#include "simeng/span.hh"

typedef std::function<uint64_t(uint64_t, uint64_t)> VAddrTranslator;

namespace simeng {

namespace memory {

class MMU {
 public:
  MMU(VAddrTranslator fn);

  ~MMU() {}

  /** Tick the memory model to process the request queue. */
  void tick(){};

  /** Queue a read request from the supplied target location.
   * The caller can optionally provide an ID that will be attached to completed
   * read results. */
  void requestRead(const MemoryAccessTarget& target, const uint64_t requestId);

  /** Queue a write request of `data` to the target location. */
  void requestWrite(const MemoryAccessTarget& target, const RegisterValue& data,
                    const uint64_t requestId);

  /** Queue a read request from the supplied target location. This has zero
   * latency as instruction cache is not currently modelled. */
  void requestInstrRead(const MemoryAccessTarget& target,
                        const uint64_t requestId);

  /** Retrieve all completed requests. */
  const span<MemoryReadResult> getCompletedReads() const;

  /** Retrieve all completed Instruction requests. */
  const span<MemoryReadResult> getCompletedInstrReads() const;

  /** Clear the completed reads. */
  void clearCompletedReads();

  /** Clear the completed Instruction reads. */
  void clearCompletedIntrReads();

  /** Returns true if there are any oustanding memory requests in-flight. */
  bool hasPendingRequests() const;

  /** Method used to buffer data requests to memory. */
  void bufferRequest(const MemoryAccessTarget& target,
                     const uint64_t requestId);

  void bufferRequest(const MemoryAccessTarget& target, const uint64_t requestId,
                     const RegisterValue& data);

  void handleTranslationFaultForDataReqs(uint64_t faultCode,
                                         const MemoryAccessTarget& target,
                                         const uint64_t requestId);

  /** Method to set the TID for the MMU. */
  void setTid(uint64_t tid);

  /** Function used to initialise the Data Port used for bidirection
   * communication. */
  std::shared_ptr<Port<CPUMemoryPacket>> initDataPort();

  /** Function used to initialise the Data Port used for bidirection
   * communication. */
  std::shared_ptr<Port<CPUMemoryPacket>> initUntimedInstrReadPort();

 private:
  /** A vector containing all completed read requests. */
  std::vector<MemoryReadResult> completedReads_;

  /** A vector containing all completed Instruction read requests. */
  std::vector<MemoryReadResult> completedInstrReads_;

  /** The number of pending data requests. */
  uint64_t pendingDataRequests_ = 0;

  /** TID of the process currently communicating with this MMU. */
  uint64_t tid_ = 0;

  /** Callback function which invokes the OS for translation on
   * TLB misses. */
  VAddrTranslator translate_;

  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<Port<CPUMemoryPacket>> port_ = nullptr;

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> untimedInstrReadPort_ = nullptr;

  /** Returns true if unsigned overflow occurs. */
  bool unsignedOverflow(uint64_t a, uint64_t b) const {
    return (a + b) < a || (a + b) < b;
  }
  /***/
  uint64_t translateVaddr(uint64_t vaddr);
};

}  // namespace memory
}  // namespace simeng
