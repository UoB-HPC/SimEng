#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <queue>

#include "simeng/Config.hh"
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

  /** Queue a read request from the supplied target location.
   * The caller can optionally provide an ID that will be attached to completed
   * read results. */
  void requestRead(const MemoryAccessTarget& target, const uint64_t requestId,
                   const uint64_t instructionID, bool isReserved = false);

  /** Queue a write request of `data` to the target location. */
  void requestWrite(const MemoryAccessTarget& target, const RegisterValue& data,
                    const uint64_t requestId, const uint64_t instructionID,
                    bool isConditional = false);

  /** Queue a read request from the supplied target location. This has zero
   * latency as instruction cache is not currently modelled. */
  void requestInstrRead(const MemoryAccessTarget& target,
                        const uint64_t requestId, const uint64_t instructionID);

  /** Retrieve all completed data read requests. */
  const span<MemoryReadResult> getCompletedReads() const;

  /** Retrieve all completed instruction read requests. */
  const span<MemoryReadResult> getCompletedInstrReads() const;

  /** Retrieve all completed conditional store requests. */
  const span<CondStoreResult> getCompletedCondStores() const;

  /** Clear the completed data reads. */
  void clearCompletedReads();

  /** Clear the completed instruction reads. */
  void clearCompletedIntrReads();

  /** Clear the completed conditional stores. */
  void clearCompletedCondStores();

  /** Returns true if there are any oustanding memory requests in-flight. */
  bool hasPendingRequests() const;

  /** Method used to buffer data requests to memory. */
  void bufferRequest(std::unique_ptr<MemPacket> request);

  /** Method to set the TID for the MMU. */
  void setTid(uint64_t tid);

  /** Updates the local cache line monitor to enforce correct LL/SC behaviour.
   */
  void updateLLSCMonitor(const std::unique_ptr<MemPacket>& request);

  /** Removes all cache line monitors that have been added via a speculated
   * reserved-load instruction. */
  void flushLLSCMonitor(const uint64_t instructionID);

  /** Function used to initialise the Data Port used for bidirection
   * communication. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initPort();

 private:
  /** A vector containing all completed read requests. */
  std::vector<MemoryReadResult> completedReads_;

  /** A vector containing all completed Instruction read requests. */
  std::vector<MemoryReadResult> completedInstrReads_;

  /** A vector containing all completed conditional store request results. */
  std::vector<CondStoreResult> completedCondStores_;

  /** The number of pending data requests. */
  uint64_t pendingDataRequests_ = 0;

  /** TID of the process currently communicating with this MMU. */
  uint64_t tid_ = 0;

  // We model "weak" LL/SC support (as is the case in the majority of hardware)
  // and so only one monitor can be usable. A stack is used to allow us to
  // re-wind monitors opened by incorrectly speculated instructions. Upon usage
  // of a monitor, the stack is emptied.

  /** Map holding all monitored cache lines, with only one ever usable at a
   * time.
   * Key = sequenceID of instruction that opened the monitor
   * Value = address of cache line */
  std::map<uint64_t, uint64_t> cacheLineMonitor_;

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
