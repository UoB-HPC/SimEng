#pragma once

#include "simeng/MemoryInterface.hh"

#include <queue>
#include <vector>

namespace simeng {

/** A variable-latency memory interface request. */
struct VariableLatencyMemoryInterfaceRequest {
  /** Is this a write request? */
  bool write;

  /** The memory target to access. */
  const MemoryAccessTarget target;

  /** The value to write to the target (writes only) */
  const RegisterValue data;

  /** The cycle count this request will be ready at. */
  uint64_t readyAt;

  /** A unique request identifier for read operations. */
  uint64_t requestId;

  /** Construct a write request. */
  VariableLatencyMemoryInterfaceRequest(const MemoryAccessTarget& target,
                                     const RegisterValue& data,
                                     uint64_t readyAt)
      : write(true), target(target), data(data), readyAt(readyAt) {}

  /** Construct a read request. */
  VariableLatencyMemoryInterfaceRequest(const MemoryAccessTarget& target,
                                     uint64_t readyAt, uint64_t requestId)
      : write(false), target(target), readyAt(readyAt), requestId(requestId) {}
};

/** A memory interface where all requests respond with a variable latency. */
class VariableLatencyMemoryInterface : public MemoryInterface {
 public:
  VariableLatencyMemoryInterface(char* memory, size_t size, uint16_t iLatency, 
                                  uint16_t fpLatency, uint16_t SVELatency);

  /** Queue a read request from the supplied target location.
   *
   * The caller can optionally provide an ID that will be attached to completed
   * read results.
   */
  void requestRead(const MemoryAccessTarget& target,
                   uint64_t requestId = 0) override;
  /** Queue a write request of `data` to the target location. */
  void requestWrite(const MemoryAccessTarget& target,
                    const RegisterValue& data) override;
  /** Retrieve all completed requests. */
  const span<MemoryReadResult> getCompletedReads() const override;

  /** Clear the completed reads. */
  void clearCompletedReads() override;

  /** Returns true if there are any oustanding memory requests in-flight. */
  bool hasPendingRequests() const override;

  /** Tick the memory model to process the request queue. */
  void tick() override;

  uint64_t getCycles() const override;

 private:
  /** The array representing the memory system to access. */
  char* memory_;
  /** The size of accessible memory. */
  size_t size_;
  /** A vector containing all completed read requests. */
  std::vector<MemoryReadResult> completedReads_;

  /** A queue containing all pending memory requests. */
  std::queue<VariableLatencyMemoryInterfaceRequest> pendingRequests_;

  /** The latency all integer requests are completed after. */
  uint16_t iLatency_;

  /** The latency all floating-point requests are completed after. */
  uint16_t fpLatency_;

  /** The latency all SVE instruction requests are completed after. */
  uint16_t SVELatency_;

  /** The number of times this interface has been ticked. */
  uint64_t tickCounter_ = 0;

  uint64_t cycles_ = 0;
};

}  // namespace simeng
