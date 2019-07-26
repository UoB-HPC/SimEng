#pragma once

#include "simeng/MemoryInterface.hh"

#include <queue>
#include <vector>

namespace simeng {

/** A fixed-latency memory interface request. */
struct FixedLatencyMemoryInterfaceRequest {
  /** Is this a write request? */
  bool write;

  /** The memory target to access. */
  const MemoryAccessTarget target;

  /** The value to write to the target (writes only) */
  const RegisterValue data;

  /** The cycle count this request will be ready at. */
  uint64_t readyAt;

  /** Construct a write request. */
  FixedLatencyMemoryInterfaceRequest(const MemoryAccessTarget& target,
                                     const RegisterValue& data,
                                     uint64_t readyAt)
      : write(true), target(target), data(data), readyAt(readyAt) {}

  /** Construct a read request. */
  FixedLatencyMemoryInterfaceRequest(const MemoryAccessTarget& target,
                                     uint64_t readyAt)
      : write(false), target(target), readyAt(readyAt) {}
};

/** A memory interface where all requests respond with a fixed latency. */
class FixedLatencyMemoryInterface : public MemoryInterface {
 public:
  FixedLatencyMemoryInterface(char* memory, size_t size, uint16_t latency);

  /** Queue a read request from the supplied target location. */
  void requestRead(const MemoryAccessTarget& target) override;
  /** Queue a write request of `data` to the target location. */
  void requestWrite(const MemoryAccessTarget& target,
                    const RegisterValue& data) override;
  /** Retrieve all completed requests. */
  const span<std::pair<MemoryAccessTarget, RegisterValue>> getCompletedReads()
      const override;

  /** Clear the completed reads. */
  void clearCompletedReads() override;

  /** Returns true if there are any oustanding memory requests in-flight. */
  bool hasPendingRequests() const override;

  /** Tick the memory model to process the request queue. */
  void tick() override;

 private:
  /** The array representing the memory system to access. */
  char* memory_;
  /** The size of accessible memory. */
  size_t size_;
  /** A vector containing all completed read requests. */
  std::vector<std::pair<MemoryAccessTarget, RegisterValue>> completedReads_;

  /** A queue containing all pending memory requests. */
  std::queue<FixedLatencyMemoryInterfaceRequest> pendingRequests_;

  /** The latency all requests are completed after. */
  uint16_t latency_;

  /** The number of times this interface has been ticked. */
  uint64_t tickCounter_ = 0;
};

}  // namespace simeng
