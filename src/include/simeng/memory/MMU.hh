#pragma once
#include <functional>
#include <memory>
#include <queue>

#include "simeng/OS/Constants.hh"
#include "simeng/Port.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/MemRequests.hh"
#include "simeng/span.hh"

typedef std::function<uint64_t(uint64_t, uint64_t)> VAddrTranslator;

namespace simeng {

/** The available memory interface types. */
enum class MemInterfaceType {
  Flat,     // A zero access latency interface
  Fixed,    // A fixed, non-zero, access latency interface
  External  // An interface generated outside of the standard SimEng
            // instantiation
};

namespace memory {

class MMU {
 public:
  MMU(uint16_t latency, VAddrTranslator fn, uint64_t tid);

  ~MMU() { delete port_; }

  /** Tick the memory model to process the request queue. */
  void tick();

  /** Queue a read request from the supplied target location.
   * The caller can optionally provide an ID that will be attached to completed
   * read results. */
  void requestRead(const MemoryAccessTarget& target, uint64_t requestId = 0);

  /** Queue a write request of `data` to the target location. */
  void requestWrite(const MemoryAccessTarget& target,
                    const RegisterValue& data);

  /** Queue a read request from the supplied target location. This has zero
   * latency as instruction cache is not currently modelled. */
  void requestInstrRead(const MemoryAccessTarget& target,
                        uint64_t requestId = 0);

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
  void bufferRequest(std::unique_ptr<MemPacket> request);

  /** Method to set the TID for the MMU. */
  void setTid(uint64_t tid);

  /** Function used to initialise the Data Port used for bidirection
   * communication. */
  Port<std::unique_ptr<MemPacket>>* initPort();

 private:
  /** The latency all requests are completed after. */
  uint16_t latency_;

  /** A vector containing all completed read requests. */
  std::vector<MemoryReadResult> completedReads_;

  /** A vector containing all completed Instruction read requests. */
  std::vector<MemoryReadResult> completedInstrReads_;

  /** A queue containing all pending memory requests. */
  std::queue<FixedLatencyMemoryInterfaceRequest> pendingRequests_;

  /** The number of times this interface has been ticked. */
  uint64_t tickCounter_ = 0;

  /** TID of the process assosciated with this MMU. */
  uint64_t tid_;

  /** Callback function which invokes the OS for translation on
   * TLB misses. */
  VAddrTranslator translate_;

  /** Data port used for communication with the memory hierarchy. */
  Port<std::unique_ptr<MemPacket>>* port_ = nullptr;

  /** Returns true if unsigned overflow occurs. */
  bool unsignedOverflow(uint64_t a, uint64_t b) const {
    return (a + b) < a || (a + b) < b;
  }
};

}  // namespace memory
}  // namespace simeng
