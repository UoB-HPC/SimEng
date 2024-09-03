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

/** The order in which instructions can exit this unit. */
enum class CompletionOrder { INORDER = 0, OUTOFORDER };

struct storeBufferEntry {
  memory::MemoryAccessTarget target;

  RegisterValue data;

  // Conditional Merge function?
  // Fails if overlaps
  // Fails if the targets aren't contiguous
  bool mergeBefore(storeBufferEntry& other) {
    if ((other.target.vaddr + other.target.size) == this->target.vaddr) {
      // If other entry can be merged before this target
      this->target.vaddr = other.target.vaddr;

      char* newData =
          (char*)calloc(this->target.size + other.target.size, sizeof(uint8_t));
      for (uint32_t i = 0; i < other.target.size; i++) {
        newData[i] = other.data.getAsVector<uint8_t>()[i];
      }
      for (uint32_t i = 0; i < this->target.size; i++) {
        newData[i + other.target.size] = this->data.getAsVector<uint8_t>()[i];
      }

      this->target.size += other.target.size;
      this->data = RegisterValue(newData, this->target.size);
      this->target.id = other.target.id;
      free(newData);

      return true;
    }
    // Cannot merge other entry
    return false;
  }

  bool mergeAfter(storeBufferEntry& other) {
    if ((this->target.vaddr + this->target.size) == other.target.vaddr) {
      // If other entry can be merged after this target
      char* newData =
          (char*)calloc(this->target.size + other.target.size, sizeof(uint8_t));
      for (uint32_t i = 0; i < this->target.size; i++) {
        newData[i] = this->data.getAsVector<uint8_t>()[i];
      }
      for (uint32_t i = 0; i < other.target.size; i++) {
        newData[i + this->target.size] = other.data.getAsVector<uint8_t>()[i];
      }

      this->target.size += other.target.size;
      this->data = RegisterValue(newData, this->target.size);
      free(newData);

      return true;
    }
    // Cannot merge other entry
    return false;
  }

  // Split function across boundary which returns remainder?
  storeBufferEntry split(uint64_t byteBoundary) {
    storeBufferEntry remainder;
    // Get displacement in target where boundary crosses
    if ((this->target.vaddr % byteBoundary) + this->target.size >
        byteBoundary) {
      uint64_t disp = byteBoundary - (this->target.vaddr % byteBoundary);
      remainder.target.vaddr = this->target.vaddr + disp;
      remainder.target.size = this->target.size - disp;

      char* splitData = (char*)calloc(disp, sizeof(uint8_t));
      char* remainderData =
          (char*)calloc(remainder.target.size, sizeof(uint8_t));
      for (uint32_t i = 0; i < this->target.size; i++) {
        if (i < disp)
          splitData[i] = this->data.getAsVector<uint8_t>()[i];
        else
          remainderData[i - disp] = this->data.getAsVector<uint8_t>()[i];
      }

      this->target.size = disp;
      this->data = RegisterValue(splitData, this->target.size);
      remainder.data = RegisterValue(remainderData, remainder.target.size);
      free(splitData);
      free(remainderData);
    }
    return remainder;
  }
};

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
      std::function<void(span<Register>, span<RegisterValue>, const uint16_t)>
          forwardOperands,
      CompletionOrder completionOrder = CompletionOrder::OUTOFORDER);

  /** Constructs a split load/store queue model, simulating discrete queues for
   * load and store instructions, supplying completion slots for loads and an
   * operand forwarding handler. */
  LoadStoreQueue(
      unsigned int maxLoadQueueSpace, unsigned int maxStoreQueueSpace,
      std::shared_ptr<memory::MMU> mmu,
      span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
      std::function<void(span<Register>, span<RegisterValue>, const uint16_t)>
          forwardOperands,
      CompletionOrder completionOrder = CompletionOrder::OUTOFORDER);

  /** Retrieve the available space for load instructions. For combined queue
   * this is the total remaining space. */
  unsigned int getLoadQueueSpace() const;

  /** Retrieve the available space for store instructions. For a combined queue
   * this is the total remaining space. */
  unsigned int getStoreQueueSpace() const;

  /** Retrieve the available space for any memory instructions. For a split
   * queue this is the sum of the space in both queues. */
  unsigned int getTotalSpace() const;

  /** Add a load instruction to the queue. */
  void addLoad(const std::shared_ptr<Instruction>& insn);

  /** Add a store instruction to the queue. */
  void addStore(const std::shared_ptr<Instruction>& insn);

  /** Add the load instruction's memory requests to the requestLoadQueue_. */
  void startLoad(const std::shared_ptr<Instruction>& insn);

  /** Supply the data to be stored by a store operation. */
  void supplyStoreData(const std::shared_ptr<Instruction>& insn);

  /** Add the store instruction's memory requests to the requestStoreQueue_. */
  void startStore(const std::shared_ptr<Instruction>& uop);

  /** Commit and write the oldest store instruction to memory, removing it from
   * the store queue. Returns `true` if memory disambiguation has discovered a
   * memory order violation during the commit. */
  bool commitStore(const std::shared_ptr<Instruction>& insn);

  /** Remove the oldest load instruction from the load queue. */
  void commitLoad(const std::shared_ptr<Instruction>& insn);

  /** Remove all flushed instructions from the queues. */
  void purgeFlushed();

  void drainSTB();

  /** Whether this is a combined load/store queue. */
  bool isCombined() const;

  /** Process received load data and send any completed loads for writeback. */
  void tick();

  /** Retrieve the load instruction associated with the most recently discovered
   * memory order violation. */
  std::shared_ptr<Instruction> getViolatingLoad() const;

  std::map<uint64_t, uint64_t> getLatMap() const { return latMap_; }

  void setTid(uint64_t tid);

  uint64_t getTid();

  uint64_t getSTBSupplies() const { return stbSupplies_; }
  uint64_t getSTBDrains() const { return stbDrains_; }
  uint64_t getConflicts() const { return conflicts_; }
  uint64_t getNumLoadReqs() const { return numLoadReqs_; }
  uint64_t getNumStoreReqs() const { return numStoreReqs_; }

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
  std::map<uint64_t, std::pair<std::shared_ptr<Instruction>, uint64_t>>
      requestedLoads_;

  /** The conditional store that has been sent to MMU. */
  std::pair<std::shared_ptr<Instruction>, bool> requestedCondStore_ = {nullptr,
                                                                       true};

  /** A function handler to call to forward the results of a completed load. */
  std::function<void(span<Register>, span<RegisterValue>, const uint16_t)>
      forwardOperands_;

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

  /** Retrieve the total memory instruction space available for a combined
   * queue. */
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
  std::queue<std::pair<memory::MemoryAccessTarget, RegisterValue>>
      requestStoreQueue_;

  /** A queue of completed requests ready for writeback. */
  std::queue<std::shared_ptr<Instruction>> completedRequests_;

  /** The order in which instructions can be passed to the completion slots. */
  CompletionOrder completionOrder_;

  uint64_t tid_;

  uint16_t storeBufferEntryWidth_ = 64;

  uint16_t storeBufferSize_ = 8;

  std::map<uint64_t, std::pair<std::vector<storeBufferEntry>, uint64_t>>
      storeBuffer_;

  uint64_t stbSupplies_ = 0;

  uint64_t stbDrains_ = 0;

  uint64_t conflicts_ = 0;

  uint64_t numLoadReqs_ = 0;
  uint64_t numStoreReqs_ = 0;

  std::map<uint64_t, uint64_t> idTracking_;
  std::map<uint64_t, uint64_t> latMap_;
};

}  // namespace pipeline
}  // namespace simeng
