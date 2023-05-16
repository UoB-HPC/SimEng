#pragma once

#include <deque>
#include <functional>
#include <map>
#include <queue>
#include <unordered_map>

#include "simeng/Instruction.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {
namespace pipeline {

/** The memory access types which are processed. */
enum accessType { LOAD = 0, STORE };

/** A load store queue (known as "load/store buffers" or "memory order buffer").
 * Holds in-flight memory access requests to ensure load/store consistency. */
class LoadStoreQueue {
 public:
  /** Constructs a combined load/store queue model, simulating a shared queue
   * for both load and store instructions, supplying completion slots for loads
   * and an operand forwarding handler. */
  LoadStoreQueue(
      unsigned int maxCombinedSpace, std::shared_ptr<memory::MMU> mmu,
      span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
      std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
      bool exclusive = false, uint16_t loadBandwidth = UINT16_MAX,
      uint16_t storeBandwidth = UINT16_MAX,
      uint16_t permittedRequests = UINT16_MAX,
      uint16_t permittedLoads = UINT16_MAX,
      uint16_t permittedStores = UINT16_MAX);

  /** Constructs a split load/store queue model, simulating discrete queues for
   * load and store instructions, supplying completion slots for loads and an
   * operand forwarding handler. */
  LoadStoreQueue(
      unsigned int maxLoadQueueSpace, unsigned int maxStoreQueueSpace,
      std::shared_ptr<memory::MMU> mmu,
      span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
      std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
      bool exclusive = false, uint16_t loadBandwidth = UINT16_MAX,
      uint16_t storeBandwidth = UINT16_MAX,
      uint16_t permittedRequests = UINT16_MAX,
      uint16_t permittedLoads = UINT16_MAX,
      uint16_t permittedStores = UINT16_MAX);

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

  /** Checks if a given conditional store has finished executing and has its
   * result ready to commit. */
  bool checkCondStore(const uint64_t sequenceId);

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
                       std::vector<simeng::RegisterValue>>>
      storeQueue_;

  /** Slots to write completed load instructions into for writeback. */
  span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots_;

  /** Map of loads that have requested their data, keyed by sequence ID. */
  std::map<uint64_t, std::shared_ptr<Instruction>> requestedLoads_;

  /** Map of conditional stores that have been sent to MMU, keyed by sequence
   * ID. */
  std::map<uint64_t, std::shared_ptr<Instruction>> requestedCondStores_;

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
  std::shared_ptr<memory::MMU> mmu_;

  /** The load instruction associated with the most recently discovered memory
   * order violation. */
  std::shared_ptr<Instruction> violatingLoad_ = nullptr;

  /** The number of times this unit has been ticked. */
  uint64_t tickCounter_ = 0;

  /** A map to hold load instructions that are stalled due to a detected
   * memory reordering confliction.
   * Key = a store's sequence id and the
   * Value = a vector of conflicted loads. */
  std::unordered_map<uint64_t, std::vector<std::shared_ptr<Instruction>>>
      conflictionMap_;

  /** A map between LSQ cycles and load requests ready on that cycle. */
  std::map<uint64_t, std::deque<std::shared_ptr<Instruction>>>
      requestLoadQueue_;

  /** A map between LSQ cycles and store requests ready on that cycle. */
  std::map<uint64_t, std::deque<std::shared_ptr<Instruction>>>
      requestStoreQueue_;

  /** A queue of completed loads ready for writeback. */
  std::queue<std::shared_ptr<Instruction>> completedLoads_;

  /** A vector of completed comditional store sequenceIds ready for writeback.
   */
  std::queue<uint64_t> completedConditionalStores_;

  /** Whether the LSQ can only process loads xor stores within a cycle. */
  bool exclusive_;

  /** The amount of data readable from the L1D cache per cycle. */
  uint16_t loadBandwidth_;

  /** The amount of data writable to the L1D cache per cycle. */
  uint16_t storeBandwidth_;

  /** The combined limit of loads and store requests permitted per cycle. */
  uint16_t totalLimit_;

  /** The number of loads and stores permitted per cycle. */
  std::array<uint16_t, 2> reqLimits_;
};

}  // namespace pipeline
}  // namespace simeng
