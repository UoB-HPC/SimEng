#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <queue>

#include "simeng/Config.hh"
#include "simeng/Instruction.hh"
#include "simeng/OS/Constants.hh"
#include "simeng/Port.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/MemRequests.hh"
#include "simeng/span.hh"
#include "simeng/util/Math.hh"

typedef std::function<uint64_t(uint64_t, uint64_t)> VAddrTranslator;

namespace simeng {

namespace memory {

class MMU {
 public:
  MMU(VAddrTranslator fn);

  ~MMU() {}

  /** Tick the memory model to process the request queue. */
  void tick(){};

  /** Queue a read request. */
  void requestRead(const std::shared_ptr<Instruction>& uop);

  /** Queue a write request. */
  void requestWrite(const std::shared_ptr<Instruction>& uop,
                    const std::vector<RegisterValue>& data);

  /** Queue a write request of `data` to the target location that is not
   * associated to an instruction. */
  void requestWrite(const MemoryAccessTarget& target,
                    const RegisterValue& data);

  /** Queue a read request from the supplied target location. This has zero
   * latency as instruction cache is not currently modelled. */
  void requestInstrRead(const MemoryAccessTarget& target);

  /** Retrieve all completed instruction read requests. */
  const span<MemoryReadResult> getCompletedInstrReads() const;

  /** Clear the completed instruction reads. */
  void clearCompletedIntrReads();

  /** Returns true if there are any oustanding memory requests in-flight. */
  bool hasPendingRequests() const;

  /** Method used to buffer data requests to memory. */
  void bufferRequest(std::unique_ptr<MemPacket> request);

  /** Method to set the TID for the MMU. */
  void setTid(uint64_t tid);

  /** Updates the local cache line monitor to enforce correct LL/SC behaviour.
   */
  void updateLLSCMonitor(const std::unique_ptr<MemPacket>& request);

  /** Function used to initialise the Data Port used for bidirection
   * communication. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initPort();

 private:
  /** A map containing all load instructions waiting for their results.
   * Key = Instruction sequenceID
   * Value = Instruction */
  std::map<uint64_t, std::shared_ptr<Instruction>> requestedLoads_;

  /** A map containing all conditional store instructions waiting for their
   * results.
   * Key = Instruction sequenceID
   * Value = Instruction */
  std::map<uint64_t, std::shared_ptr<Instruction>> requestedCondStore_;

  /** A vector containing all completed Instruction read requests. */
  std::vector<MemoryReadResult> completedInstrReads_;

  /** The number of pending data requests. */
  uint64_t pendingDataRequests_ = 0;

  /** TID of the process currently communicating with this MMU. */
  uint64_t tid_ = 0;

  // We model "weak" LL/SC support (as is the case in the majority of hardware)
  // and so only one monitor can be usable. Atomics are processed when at the
  // head of ROB so no speculation, and are assumed to be correctly aligned.

  /** Address of currently monitored cache line, and whether it is valid.*/
  std::pair<uint64_t, bool> cacheLineMonitor_;

  /** Width of a cache line. */
  const uint64_t cacheLineWidth_;

  /** Callback function which invokes the OS for translation on
   * TLB misses. */
  VAddrTranslator translate_;

  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> port_ = nullptr;

  /** Returns true if unsigned overflow occurs. */
  bool unsignedOverflow(uint64_t a, uint64_t b) const {
    return (a + b) < a || (a + b) < b;
  }
};

}  // namespace memory
}  // namespace simeng
