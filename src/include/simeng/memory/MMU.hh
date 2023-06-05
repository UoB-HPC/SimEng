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
  void tick();

  /** Queue a read request. Returns true if there is space for the request.
   * Return false otherwise. */
  bool requestRead(const std::shared_ptr<Instruction>& uop);

  /** Queue a write request. Returns true if there is space for the request.
   * Return false otherwise. */
  bool requestWrite(const std::shared_ptr<Instruction>& uop,
                    const std::vector<RegisterValue>& data);

  /** Process a write request of `data` to the target location that is not
   * associated to an instruction, or bound band bandwidth limits. */
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

  /** Method to set the TID for the MMU. */
  void setTid(uint64_t tid);

  /** Function used to initialise the Data Port used for bidirection
   * communication. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initPort();

 private:
  /** Process load or store requests. */
  void processRequests(const bool isStore);

  /** Method used to buffer data requests to memory. */
  void issueRequest(std::unique_ptr<MemPacket> request);

  /** Open a new cache line monitor. */
  void openLLSCMonitor(const std::shared_ptr<Instruction>& loadRes);

  /** Checks whether a valid monitor is open for a store conditional. Returns
   * whether the store can proceed or not. */
  bool checkLLSCMonitor(const std::shared_ptr<Instruction>& strCond);

  /** Potentially updates the local cache line monitor to enforce correct LL/SC
   * behaviour. */
  void updateLLSCMonitor(const MemoryAccessTarget& storeTarget);

  /** Returns true if unsigned overflow occurs. */
  bool unsignedOverflow(uint64_t a, uint64_t b) const {
    return (a + b) < a || (a + b) < b;
  }

  /** Check if given target crosses a cache line boundary. Returns true if no
   * cache line boundary is crossed. */
  bool isAligned(const MemoryAccessTarget& target) const {
    assert(target.size != 0 &&
           "[SimEng:MMU] Cannot have a memory target size of 0.");
    uint64_t startAddr = target.vaddr;
    // Must -1 from end address as vaddr + size will give the address at end of
    // region, but this address is not written to.
    // i.e. vaddr = 0, size = 4 :  | | | | | | | |
    //                      Addr:  0 1 2 3 4 5 6 7
    //                             ^-------^
    //                              Payload
    // End address is 4, but we do not write to address 4 hence this is allowed
    // to be a cache line boundary.
    uint64_t endAddr = target.vaddr + target.size - 1;
    // If start and end address down align to same value (w.r.t cache line
    // width), then memory target is aligned.
    return (downAlign(startAddr, cacheLineWidth_) ==
            downAlign(endAddr, cacheLineWidth_));
  }

  /** Splits a read memory access target into multiple MemPackets such that each
   * MemPacket is aligned w.r.t the cache line width.*/
  std::vector<std::unique_ptr<MemPacket>> splitReadMemTarget(
      const MemoryAccessTarget& target, uint64_t insnSeqId,
      uint16_t pktOrderId) const {
    std::vector<std::unique_ptr<MemPacket>> packets = {};
    if (isAligned(target)) {
      auto req = MemPacket::createReadRequest(target.vaddr, target.size,
                                              insnSeqId, pktOrderId);
      packets.push_back(std::move(req));
      return packets;
    }

    uint64_t nextAddr = target.vaddr;
    uint64_t remSize = static_cast<uint64_t>(target.size);
    uint16_t nextSplitId = 0;
    while (remSize != 0) {
      // Get size of next target region
      uint16_t regSize = std::min(
          (downAlign(nextAddr, cacheLineWidth_) + cacheLineWidth_) - nextAddr,
          remSize);
      auto req = MemPacket::createReadRequest(nextAddr, regSize, insnSeqId,
                                              pktOrderId);
      req->packetSplitId_ = nextSplitId;
      packets.push_back(std::move(req));
      // Update vars
      nextAddr += regSize;
      remSize -= regSize;
      nextSplitId++;
    }
    return packets;
  }

  /** Splits a write memory access target into multiple MemPackets such that
   * each MemPacket is aligned w.r.t the cache line width.*/
  std::vector<std::unique_ptr<MemPacket>> splitWriteMemTarget(
      const MemoryAccessTarget& target, const std::vector<char>& data,
      uint64_t insnSeqId, uint16_t pktOrderId) const {
    std::vector<std::unique_ptr<MemPacket>> packets = {};
    if (isAligned(target)) {
      auto req = MemPacket::createWriteRequest(target.vaddr, target.size,
                                               insnSeqId, pktOrderId, data);
      packets.push_back(std::move(req));
      return packets;
    }

    uint64_t nextAddr = target.vaddr;
    uint64_t remSize = static_cast<uint64_t>(target.size);
    uint16_t nextSplitId = 0;
    std::vector<char> remData = data;
    while (remSize != 0) {
      // Get size of next target region
      uint16_t regSize = std::min(
          (downAlign(nextAddr, cacheLineWidth_) + cacheLineWidth_) - nextAddr,
          remSize);

      auto regData =
          std::vector<char>(remData.begin(), remData.begin() + regSize);
      auto req = MemPacket::createWriteRequest(nextAddr, regSize, insnSeqId,
                                               pktOrderId, regData);
      req->packetSplitId_ = nextSplitId;
      packets.push_back(std::move(req));
      // Update vars
      nextAddr += regSize;
      remSize -= regSize;
      nextSplitId++;
      remData = std::vector<char>(remData.begin() + regSize, remData.end());
    }
    return packets;
  }

  /** For a given instruction, supply all data from packets in readResponses_.
   */
  void supplyLoadData(const uint64_t insnSeqId) {
    auto& insn = requestedLoads_.find(insnSeqId)->second;
    assert(insn != requestedLoads_.end() &&
           "[SimEng:MMU] Tried to supply data to a load instruction that does "
           "not exist in the requestedLoads_ map.");
    auto& packets = readResponses_.find(insnSeqId)->second;

    int pktLim = insn->getNumDataPending();
    for (int i = 0; i < pktLim; i++) {
      auto& pktVec = packets[i];
      assert(pktVec.size() > 0 &&
             "[SimEng:MMU] Empty read response packet vector.");
      if (pktVec.size() == 1) {
        // Request not split, supply data normally
        if (pktVec[0]->isFaulty()) {
          // If faulty, return no data. This signals a data abort.
          insn->supplyData(pktVec[0]->vaddr_, RegisterValue());
          continue;
        }
        insn->supplyData(pktVec[0]->vaddr_,
                         {pktVec[0]->payload().data(), pktVec[0]->size_});
      } else {
        // Request was split, merge responses before supplying data to
        // instruction
        uint64_t addr = pktVec[0]->vaddr_;
        if (pktVec[0]->isFaulty()) {
          // If faulty, return no data. This signals a data abort.
          insn->supplyData(addr, RegisterValue());
          continue;
        }
        // Initialise values with first package
        std::vector<char> mergedData = pktVec[0]->payload();
        uint16_t mergedSize = pktVec[0]->size_;
        for (int j = 1; j < pktVec.size(); j++) {
          if (pktVec[j]->isFaulty()) {
            // If faulty, return no data. This signals a data abort.
            insn->supplyData(addr, RegisterValue());
            return;
          }
          // Increase merged size
          mergedSize += pktVec[j]->size_;
          // Concatonate the payload data
          auto& tempData = pktVec[j]->payload();
          mergedData.insert(mergedData.end(), tempData.begin(), tempData.end());
        }
        // Supply data to instruction
        insn->supplyData(addr, {mergedData.data(), mergedSize});
      }
    }
    assert(insn->hasAllData() &&
           "[SimEng:MMU] Load instruction was supplied memory data but is "
           "still waiting on further data to be supplied.");
    // Instruction now has all data, remove entries from maps
    requestedLoads_.erase(insnSeqId);
    readResponses_.erase(insnSeqId);
  }

  /** A map containing all load instructions waiting for their results.
   * Key = Instruction sequenceID
   * Value = Instruction */
  std::map<uint64_t, std::shared_ptr<Instruction>> requestedLoads_;

  /** Map containing all read response packets before they have been added to
   * their associated instruction.
   * Key = Instruction sequenceID
   * Value = map containing all responses for a specific instruction
   *            Key = packetOrderID
   *            Value = Vector of 1 or more packets, depending on if the request
   *                    was split */
  std::map<uint64_t,
           std::map<uint16_t, std::vector<std::unique_ptr<MemPacket>>>>
      readResponses_;

  /** A map containing all store instructions waiting for their results.
   * Key = Instruction sequenceID
   * Value = Instruction */
  std::map<uint64_t, std::shared_ptr<Instruction>> requestedStores_;

  /** A vector containing all completed Instruction read requests. */
  std::vector<MemoryReadResult> completedInstrReads_;

  /** The number of pending data requests. */
  uint64_t pendingDataRequests_ = 0;

  /** TID of the process currently communicating with this MMU. */
  uint64_t tid_ = 0;

  // We model "weak" LL/SC support (as is the case in the majority of hardware)
  // and so only one monitor can be usable. Atomics are processed when at the
  // head of ROB so no speculation, and are assumed to be correctly aligned.
  /** The cache line monitor represented as a pair. Containes a set of cache
   * line addresses within monitor, and whether the monitor is valid. */
  std::pair<std::set<uint64_t>, bool> cacheLineMonitor_;

  /** Width of a cache line. */
  const uint64_t cacheLineWidth_;

  /** Fixed array containing vectors for all loads and store requests.
   * First in array contains all load requests for a number of instructions.
   * Each inner vector represents a single instruction.
   *
   * Second in array contains all store requests for a number of instructions.
   * Each inner vector represents a single instruction. */
  std::array<std::vector<std::vector<std::unique_ptr<MemPacket>>>, 2>
      loadsStores_;

  /** Constant indexes for the loadStores_ array. */
  static constexpr uint8_t LD = 0;
  static constexpr uint8_t STR = 1;

  /** The per-cycle total load bandwidth. */
  uint64_t loadBandwidth_;

  /** The per-cycle total store bandwidth. */
  uint64_t storeBandwidth_;

  /** The number of total requests (instructions) permitted per cycle. */
  uint64_t requestLimit_;

  /** The number of load requests (instructions) permitted per cycle. */
  uint64_t loadRequestLimit_;

  /** The number of store requests (instructions) permitted per cycle. */
  uint64_t storeRequestLimit_;

  /** If true, then load and stores can share pipes. If false then there are
   * individual load and store pipes. */
  bool exclusiveRequests_;

  /** Callback function which invokes the OS for translation on
   * TLB misses. */
  VAddrTranslator translate_;

  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> port_ = nullptr;
};

}  // namespace memory
}  // namespace simeng
