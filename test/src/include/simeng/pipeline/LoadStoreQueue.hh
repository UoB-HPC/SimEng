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

enum class stbOverlap { NONE = 0, PARTIAL, FULL };

struct storeBufferEntry {
  uint64_t baseAddr_ = 0ull;

  uint64_t entryWidth_ = 0ull;

  uint64_t id_ = 0ull;

  std::vector<uint64_t> activeBytes_;

  std::vector<char> data_ = {};

  bool debug_ = false;

  storeBufferEntry() {}

  storeBufferEntry(uint64_t baseAddr, uint64_t entryWidth, uint64_t id)
      : baseAddr_(baseAddr), entryWidth_(entryWidth), id_(id) {
    data_ = std::vector<char>(entryWidth_, '\0');
    activeBytes_ = std::vector<uint64_t>(
        static_cast<size_t>(std::ceil(entryWidth_ / 64.f)), 0);
  }

  bool addToEntry(const memory::MemoryAccessTarget& target,
                  const RegisterValue& data) {
    bool entryCross = false;
    if (debug_) {
      std::cerr << "[SimEng]\t\t*======= Adding to STB =======*" << std::endl;
      std::cerr << "[SimEng]\t\t| baseAddr = " << std::hex << baseAddr_
                << std::dec << std::endl;
      std::cerr << "[SimEng]\t\t| target.vaddr = " << std::hex << target.vaddr
                << std::dec << std::endl;
      std::cerr << "[SimEng]\t\t| target.size = " << std::hex << target.size
                << std::dec << std::endl;

      std::cerr << "[SimEng]\t\t| data = [" << std::hex;
      for (int j = target.size - 1; j >= 0; j--) {
        if (unsigned(data.getAsVector<uint8_t>()[j]) < static_cast<uint8_t>(16))
          std::cerr << "0";
        std::cerr << unsigned(data.getAsVector<uint8_t>()[j]) << " ";
      }
      std::cerr << std::dec << "\b]" << std::endl;
      std::cerr << "[SimEng]\t\t|" << std::endl;
    }

    // Find range that data to be inserted covers
    uint64_t startOffset = 0;
    if (target.vaddr > baseAddr_) startOffset = target.vaddr - baseAddr_;
    if (debug_) {
      std::cerr << "[SimEng]\t\t| startOffset = " << startOffset << std::endl;
    }

    uint64_t endOffset = (target.vaddr + target.size) - baseAddr_;
    if (endOffset > entryWidth_) {
      endOffset = entryWidth_;
      entryCross = true;
    }
    if (debug_) {
      std::cerr << "[SimEng]\t\t| endOffset = " << endOffset << std::endl;
      std::cerr << "[SimEng]\t\t| entryCross = " << entryCross << std::endl;
    }

    // Set range as active
    if (debug_) {
      std::cerr << "[SimEng]\t\t| activeBytes_ before = " << std::hex;
      for (int i = activeBytes_.size() - 1; i >= 0; i--) {
        std::cerr << activeBytes_[i];
      }
      std::cerr << std::dec << std::endl;
    }

    std::vector<uint64_t> debugMask;
    uint64_t bytesRemain = target.size;
    uint64_t startPtr = startOffset;
    uint64_t endPtr = endOffset;
    while (bytesRemain) {
      int idx = std::floor(startPtr / 64);
      if (idx >= activeBytes_.size()) break;
      if (endOffset > (idx + 1) * 64) {
        endPtr = (idx + 1) * 64;
      }
      uint64_t preShiftMask =
          (endPtr - startPtr == 64) ? -1 : (1ull << (endPtr - startPtr)) - 1;
      activeBytes_[idx] |= preShiftMask << startPtr;
      if (debug_) {
        debugMask.push_back(preShiftMask << startPtr);
      }
      bytesRemain -= (endPtr - startPtr);
      startPtr = (idx + 1) * 64;
    }

    if (debug_) {
      std::cerr << "[SimEng]\t\t| activeBytes_ after =  " << std::hex;
      for (int i = activeBytes_.size() - 1; i >= 0; i--) {
        std::cerr << activeBytes_[i];
      }
      std::cerr << std::dec << " (mask = " << std::hex;
      for (int i = debugMask.size() - 1; i >= 0; i--) {
        std::cerr << debugMask[i];
      }
      std::cerr << ")" << std::endl;
    }

    // Extract and merge data
    const char* dataAsChars = data.getAsVector<char>();

    uint8_t idx = 0;
    if (target.vaddr < baseAddr_) idx = baseAddr_ - target.vaddr;

    if (debug_) {
      std::cerr << "[SimEng]\t\t| data_ before = [" << std::hex;
      for (int j = data_.size() - 1; j >= 0; j--) {
        if (unsigned(static_cast<uint8_t>(data_[j])) < static_cast<uint8_t>(16))
          std::cerr << "0";
        std::cerr << unsigned(static_cast<uint8_t>(data_[j])) << " ";
      }
      std::cerr << std::dec << "\b]" << std::endl;
    }

    for (int i = startOffset; i < endOffset; i++) {
      data_[i] = dataAsChars[idx];
      idx++;
    }

    if (debug_) {
      std::cerr << "[SimEng]\t\t| data_ after =  [" << std::hex;
      for (int j = data_.size() - 1; j >= 0; j--) {
        if (unsigned(static_cast<uint8_t>(data_[j])) < static_cast<uint8_t>(16))
          std::cerr << "0";
        std::cerr << unsigned(static_cast<uint8_t>(data_[j])) << " ";
      }
      std::cerr << std::dec << "\b]" << std::endl;
      std::cerr << "[SimEng]\t\t*=============================*" << std::endl;
    }

    return entryCross;
  }

  stbOverlap doesContain(const memory::MemoryAccessTarget& target) {
    // Create mask for required range
    uint64_t startOffset = target.vaddr - baseAddr_;
    uint64_t endOffset = (target.vaddr + target.size) - baseAddr_;
    bool entryCross = false;
    if (endOffset > entryWidth_) {
      endOffset = entryWidth_;
      entryCross = true;
    }
    std::vector<uint64_t> mask(std::ceil(endOffset / 64.f), 0);

    if (debug_) {
      std::cerr << "[SimEng]\t\t\tdoesContain called on " << std::hex
                << baseAddr_ << std::dec << " for target " << std::hex
                << target.vaddr << std::dec << ":" << target.size << std::endl;
      std::cerr << "[SimEng]\t\t\t\tstartOffset = " << startOffset << std::endl;
      std::cerr << "[SimEng]\t\t\t\tendOffset = " << endOffset;
      if (entryCross) {
        std::cerr << " (" << (target.vaddr + target.size) - baseAddr_ << ")";
      }
      std::cerr << std::endl;
      std::cerr << "[SimEng]\t\t\t\tmask size = " << mask.size() << std::endl;
    }

    uint64_t bytesRemain = target.size;
    uint64_t startPtr = startOffset;
    uint64_t endPtr = endOffset;
    while (bytesRemain) {
      int idx = std::floor(startPtr / 64);
      if (idx >= mask.size()) break;
      if (endOffset > (idx + 1) * 64) {
        endPtr = (idx + 1) * 64;
      }
      uint64_t preShiftMask =
          (endPtr - startPtr == 64) ? -1 : (1ull << (endPtr - startPtr)) - 1;
      mask[idx] |= preShiftMask << startPtr;
      bytesRemain -= (endPtr - startPtr);
      startPtr = (idx + 1) * 64;
    }

    if (debug_) {
      std::cerr << "[SimEng]\t\t\t\tmask = " << std::hex;
      for (int i = mask.size() - 1; i >= 0; i--) {
        std::cerr << mask[i];
      }
      std::cerr << std::dec << std::endl;
      std::cerr << "[SimEng]\t\t\t\tmask & activeBytes_  = " << std::hex;
      for (int i = mask.size() - 1; i >= 0; i--) {
        std::cerr << (mask[i] & activeBytes_[i]);
      }
      std::cerr << std::dec << std::endl;
    }

    stbOverlap overlapStatus = stbOverlap::FULL;
    for (int i = 0; i < mask.size(); i++) {
      if (mask[i] == (mask[i] & activeBytes_[i])) {
        if (overlapStatus == stbOverlap::NONE) {
          overlapStatus = stbOverlap::PARTIAL;
          break;
        }
        continue;
      } else if ((mask[i] & activeBytes_[i]) != 0) {
        overlapStatus = stbOverlap::PARTIAL;
        break;
      } else {
        overlapStatus = stbOverlap::NONE;
      }
    }

    if (overlapStatus == stbOverlap::FULL && entryCross)
      overlapStatus = stbOverlap::PARTIAL;

    if (debug_) {
      std::cerr << "[SimEng]\t\t\t\toverlapStatus = ";
      if (overlapStatus == stbOverlap::FULL)
        std::cerr << "FULL";
      else if (overlapStatus == stbOverlap::PARTIAL)
        std::cerr << "PARTIAL";
      else
        std::cerr << "NONE";
      std::cerr << std::endl;
    }
    return overlapStatus;
  }

  RegisterValue extractData(const memory::MemoryAccessTarget& target) {
    RegisterValue data(data_.data() + (target.vaddr - baseAddr_), target.size);
    return data;
  }

  std::vector<std::pair<memory::MemoryAccessTarget, RegisterValue>>
  createRequests(uint64_t startId) {
    // Distill entry into discrete memory requests
    std::vector<std::pair<memory::MemoryAccessTarget, RegisterValue>> requests;
    uint64_t id = startId;

    if (debug_) {
      std::cerr << "[SimEng]\t\tCreating requests for STB entry " << std::hex
                << baseAddr_ << std::dec << ":" << id_ << std::endl;
      std::cerr << "[SimEng]\t\tdata_ = [" << std::hex;
      for (int j = data_.size() - 1; j >= 0; j--) {
        if (unsigned(static_cast<uint8_t>(data_[j])) < static_cast<uint8_t>(16))
          std::cerr << "0";
        std::cerr << unsigned(static_cast<uint8_t>(data_[j])) << " ";
      }
      std::cerr << std::dec << "\b]" << std::endl;
    }

    bool extracting = false;
    memory::MemoryAccessTarget currentTarget;
    std::vector<char> currentData = {};
    for (int i = 0; i < entryWidth_; i++) {
      if (activeBytes_[std::floor(i / 64.f)] & (1ull << i % 64)) {
        if (extracting) {
          // Add to current target
          currentData.push_back(data_[i]);
        } else {
          // Create new current target
          extracting = true;
          if (debug_) {
            std::cerr << "[SimEng]\t\tStarting request creation at idx " << i
                      << " for addr " << std::hex << baseAddr_ + i << std::dec
                      << std::endl;
          }
          // Set size to 0 until we know the length
          currentTarget =
              memory::MemoryAccessTarget(baseAddr_ + i, 0, (1ull << 63) | id);
          id++;

          currentData.push_back(data_[i]);
        }
      } else if (extracting) {
        // Save current target
        extracting = false;
        currentTarget.size = (baseAddr_ + i) - currentTarget.vaddr;
        if (debug_) {
          std::cerr << "[SimEng]\t\tFinished request creation at idx " << i
                    << " of size " << currentTarget.size << std::endl;
          std::cerr << "[SimEng]\t\tdata is =  [" << std::hex;
          for (int j = currentData.size() - 1; j >= 0; j--) {
            if (unsigned(static_cast<uint8_t>(currentData[j])) <
                static_cast<uint8_t>(16))
              std::cerr << "0";
            std::cerr << unsigned(static_cast<uint8_t>(currentData[j])) << " ";
          }
          std::cerr << std::dec << "\b]" << std::endl;
        }
        requests.push_back(
            {currentTarget, {currentData.data(), currentTarget.size}});
        currentData = {};
      }
    }

    if (extracting) {
      currentTarget.size = (baseAddr_ + entryWidth_) - currentTarget.vaddr;
      if (debug_) {
        std::cerr << "[SimEng]\t\tFinished request creation at idx "
                  << entryWidth_ << " of size " << currentTarget.size
                  << std::endl;
        std::cerr << "[SimEng]\t\tdata is =  [" << std::hex;
        for (int j = currentData.size() - 1; j >= 0; j--) {
          if (unsigned(static_cast<uint8_t>(currentData[j])) <
              static_cast<uint8_t>(16))
            std::cerr << "0";
          std::cerr << unsigned(static_cast<uint8_t>(currentData[j])) << " ";
        }
        std::cerr << std::dec << "\b]" << std::endl;
      }
      requests.push_back(
          {currentTarget, {currentData.data(), currentTarget.size}});
      currentData = {};
    }

    return requests;
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

  /** Supply the information for usage by a store operation. */
  void supplyStoreInfo(const std::shared_ptr<Instruction>& insn);

  /** Add the store instruction's memory requests to the requestStoreQueue_. */
  bool startStore(const std::shared_ptr<Instruction>& uop);

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

  std::unordered_map<uint64_t, uint64_t> getLatMap() const { return latMap_; }

  void setTid(uint64_t tid);

  uint64_t getTid();

  uint64_t getSTBSupplies() const { return stbSupplies_; }
  uint64_t getSTBQuietDrains() const { return stbQuietDrain_; }
  uint64_t getSTBCapacityDrains() const { return stbCapacityDrains_; }
  uint64_t getSTBMismatchDrains() const { return stbMismatchDrains_; }
  uint64_t getSTBSystemDrains() const { return stbSystemDrains_; }
  uint64_t getLoadReqs() const { return loadReqs_; }
  uint64_t getSQSupplies() const { return sqSupplies_; }
  uint64_t getConflicts() const { return conflicts_; }
  uint64_t getLoadTLBResubs() const { return loadTLBReadReIssues_; }
  uint64_t getLoadDataResubs() const { return loadDataReadReIssues_; }
  uint64_t getStoreAddrReqs() const { return storeAddrReqs_; }
  uint64_t getStoreAddrResubs() const { return storeAddrReIssues_; }
  uint64_t getStoreDataReqs() const { return storeDataReqs_; }
  uint64_t getStoreDataResubs() const { return storeDataReIssues_; }

  void enableAccessPrint(bool enable) { accessPrint_ = enable; }

  void enableSTBPrint(bool enable) { stbPrint_ = enable; }

  void resetStats() {
    stbSupplies_ = 0;
    stbQuietDrain_ = 0;
    stbCapacityDrains_ = 0;
    stbMismatchDrains_ = 0;
    stbSystemDrains_ = 0;
    loadReqs_ = 0;
    sqSupplies_ = 0;
    conflicts_ = 0;
    loadTLBReadReIssues_ = 0;
    loadDataReadReIssues_ = 0;
    storeAddrReqs_ = 0;
    storeAddrReIssues_ = 0;
    storeDataReqs_ = 0;
    storeDataReIssues_ = 0;
    idTracking_ = {};
    latMap_ = {};
  }

 private:
  void recursiveSTBaddition(uint64_t baseAddr, uint64_t id,
                            const memory::MemoryAccessTarget& target,
                            const RegisterValue& data);

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

  std::map<uint64_t, std::pair<std::shared_ptr<Instruction>, uint64_t>>
      requestedStoreAddrs_;

  std::map<uint64_t, std::pair<std::shared_ptr<memory::MemoryAccessTarget>,
                               RegisterValue>>
      requestedStoreDatas_;

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

  std::map<uint64_t, std::deque<std::shared_ptr<Instruction>>>
      requestStoreAddrQueue_;

  /** A map between LSQ cycles and store requests ready on that cycle. */
  std::deque<
      std::pair<std::shared_ptr<memory::MemoryAccessTarget>, RegisterValue>>
      requestStoreDataQueue_;

  /** A queue of completed requests ready for writeback. */
  std::deque<std::pair<std::shared_ptr<Instruction>, uint64_t>>
      completedRequests_;

  /** The order in which instructions can be passed to the completion slots. */
  CompletionOrder completionOrder_;

  uint64_t tid_;

  uint16_t storeBufferEntryWidth_ = 64;
  uint16_t storeBufferSize_ = 8;

  std::map<uint64_t, std::pair<storeBufferEntry, uint64_t>> storeBuffer_;
  uint64_t stbReqIds_ = 0;

  uint64_t stbSupplies_ = 0;
  uint64_t stbQuietDrain_ = 0;
  uint64_t stbCapacityDrains_ = 0;
  uint64_t stbMismatchDrains_ = 0;
  uint64_t stbSystemDrains_ = 0;

  uint64_t loadReqs_ = 0;
  uint64_t sqSupplies_ = 0;
  uint64_t conflicts_ = 0;
  uint64_t loadTLBReadReIssues_ = 0;
  uint64_t loadDataReadReIssues_ = 0;

  uint64_t storeAddrReqs_ = 0;
  uint64_t storeAddrReIssues_ = 0;

  uint64_t storeDataReqs_ = 0;
  uint64_t storeDataReIssues_ = 0;

  std::unordered_map<uint64_t, uint64_t> idTracking_;
  std::unordered_map<uint64_t, uint64_t> latMap_;

  bool accessPrint_ = false;
  bool stbPrint_ = false;

  uint64_t pauseUntil_ = 0;

  uint64_t outputCooldown_ = 0;
};

}  // namespace pipeline
}  // namespace simeng
