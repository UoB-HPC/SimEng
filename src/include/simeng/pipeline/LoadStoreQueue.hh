#pragma once

#include <deque>
#include <functional>
#include <map>
#include <queue>
#include <unordered_map>

#include "simeng/Instruction.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {
namespace pipeline {

/** A requestQueue_ entry. */
struct requestEntry {
  /** The memory address(es) to be accessed. */
  std::queue<const simeng::MemoryAccessTarget> reqAddresses;

  /** The instruction sending the request(s). */
  std::shared_ptr<Instruction> insn;
};

/** A load store queue (known as "load/store buffers" or "memory order buffer").
 * Holds in-flight memory access requests to ensure load/store consistency. */
class LoadStoreQueue {
 public:
  /** Constructs a combined load/store queue model, simulating a shared queue
   * for both load and store instructions, supplying completion slots for loads
   * and an operand forwarding handler. */
  LoadStoreQueue(
      unsigned int maxCombinedSpace, MemoryInterface& memory,
      span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
      std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
      uint8_t L1Bandwidth = UINT8_MAX, uint8_t permittedRequests = UINT8_MAX,
      uint8_t permittedLoads = UINT8_MAX, uint8_t permittedStores = UINT8_MAX);

  /** Constructs a split load/store queue model, simulating discrete queues for
   * load and store instructions, supplying completion slots for loads and an
   * operand forwarding handler. */
  LoadStoreQueue(
      unsigned int maxLoadQueueSpace, unsigned int maxStoreQueueSpace,
      MemoryInterface& memory,
      span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
      std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
      uint8_t L1Bandwidth = UINT8_MAX, uint8_t permittedRequests = UINT8_MAX,
      uint8_t permittedLoads = UINT8_MAX, uint8_t permittedStores = UINT8_MAX);

  /** Retrieve the available space for load uops. For combined queue this is the
   * total remaining space. */
  unsigned int getLoadQueueSpace() const;

  /** Retrieve the available space for store uops. For a combined queue this is
   * the total remaining space. */
  unsigned int getStoreQueueSpace() const;

  /** Retrieve the available space for any memory uops. For a split queue this
   * is the sum of the space in both queues. */
  unsigned int getTotalSpace() const;

  /** Add a load uop to the queue. */
  void addLoad(const std::shared_ptr<Instruction>& insn);

  /** Add a store uop to the queue. */
  void addStore(const std::shared_ptr<Instruction>& insn);

  /** Add the load instruction's memory requests to the requestQueue_. */
  void startLoad(const std::shared_ptr<Instruction>& insn);

  /** Supply the data to be stored by a store operation. */
  void supplyStoreData(const std::shared_ptr<Instruction>& insn);

  /** Commit and write the oldest store instruction to memory, removing it from
   * the store queue. Returns `true` if memory disambiguation has discovered a
   * memory order violation during the commit. */
  bool commitStore(const std::shared_ptr<Instruction>& uop);

  /** Remove the oldest load instruction from the load queue. */
  void commitLoad(const std::shared_ptr<Instruction>& uop);

  /** Remove all flushed instructions from the queues. */
  void purgeFlushed();

  /** Whether this is a combined load/store queue. */
  bool isCombined() const;

  /** Process received load data and send any completed loads for writeback. */
  void tick();

  /** Retrieve the load instruction associated with the most recently discovered
   * memory order violation. */
  std::shared_ptr<Instruction> getViolatingLoad() const;

 private:
  /** The load queue: holds in-flight load instructions. */
  std::deque<std::shared_ptr<Instruction>> loadQueue_;

  /** The store queue: holds in-flight store instructions with its associated
   * data. */
  std::deque<std::pair<std::shared_ptr<Instruction>,
                       span<const simeng::RegisterValue>>>
      storeQueue_;

  /** Slots to write completed load instructions into for writeback. */
  span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots_;

  /** Map of loads that have requested their data, keyed by sequence ID. */
  std::unordered_map<uint64_t, std::shared_ptr<Instruction>> requestedLoads_;

  /** A function handler to call to forward the results of a completed load. */
  std::function<void(span<Register>, span<RegisterValue>)> forwardOperands_;

  /** The maximum number of loads that can be in-flight. Undefined if this
   * is a combined queue. */
  unsigned int maxLoadQueueSpace_;

  /** The maximum number of stores that can be in-flight. Undefined if this is a
   * combined queue. */
  unsigned int maxStoreQueueSpace_;

  /** The maximum number of memory ops that can be in-flight. Undefined if this
   * is a split queue. */
  unsigned int maxCombinedSpace_;

  /** Whether this queue is combined or split. */
  bool combined_;

  /** Retrieve the load queue space for a split queue. */
  unsigned int getLoadQueueSplitSpace() const;

  /** Retrieve the store queue space for a split queue. */
  unsigned int getStoreQueueSplitSpace() const;

  /** Retrieve the total memory uop space available for a combined queue. */
  unsigned int getCombinedSpace() const;

  /** A pointer to process memory. */
  MemoryInterface& memory_;

  /** The load instruction associated with the most recently discovered memory
   * order violation. */
  std::shared_ptr<Instruction> violatingLoad_ = nullptr;

  /** The number of times this unit has been ticked. */
  uint64_t tickCounter_ = 0;

  /** A map to hold load instructions that are stalled due to a detected
   * memory reordering confliction. First key is a store's sequence id and the
   * second key the conflicting address. The value takes the form of a vector of
   * pairs containing a pointer to the conflicted load and the size of the data
   * needed at that address by the load. */
  std::unordered_map<
      uint64_t,
      std::unordered_map<
          uint64_t,
          std::vector<std::pair<std::shared_ptr<Instruction>, uint16_t>>>>
      conflictionMap_;

  /** A map between LSQ cycles and load requests ready on that cycle. */
  std::map<uint64_t, std::deque<requestEntry>> requestLoadQueue_;

  /** A map between LSQ cycles and store requests ready on that cycle. */
  std::map<uint64_t, std::deque<requestEntry>> requestStoreQueue_;

  /** A queue of completed loads ready for writeback. */
  std::queue<std::shared_ptr<Instruction>> completedLoads_;

  /** The amount of data transferable to the L1 cache per cycle. */
  uint64_t L1Bandwidth_;

  /** The combined limit of loads and store requests permitted per cycle. */
  uint8_t totalLimit_;

  /** The number of loads and stores permitted per cycle. */
  std::array<uint8_t, 2> reqLimits_;

  /** Mapping between indexes of reqLimits_ and request type. */
  uint8_t LOAD_INDEX = 0;
  uint8_t STORE_INDEX = 1;
};

}  // namespace pipeline
}  // namespace simeng
