#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <queue>
#include <set>

#include "simeng/Instruction.hh"
#include "simeng/OS/Constants.hh"
#include "simeng/Port.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/MemRequests.hh"
#include "simeng/span.hh"
#include "simeng/util/Math.hh"

typedef std::function<uint64_t(uint64_t, uint64_t, bool)> VAddrTranslator;

namespace simeng {

namespace memory {

enum class requestSuccess {
  SUCCESS = 0,
  LIMIT,
  TRANSLATION,
  TLB_MSHR,
  CACHE_MSHR,
};

/** Simple struct representing an entry for the requested[Load|Store]_ map.*/
struct reqEntry {
  reqEntry() {}

  reqEntry(uint64_t reqId, uint16_t totalPacketsRemaining,
           std::shared_ptr<Instruction> insn = nullptr)
      : reqId_(reqId),
        totalPacketsRemaining_(totalPacketsRemaining),
        insn_(insn) {}

  uint64_t reqId_ = 0;

  /** The number of MemoryPackets sent to memory that have not returned yet. */
  uint16_t totalPacketsRemaining_ = 0;

  std::shared_ptr<Instruction> insn_ = nullptr;

  /** Whether a memory access associated with this entry has failed. */
  bool failed_ = false;
};

struct tlbMSHR {
  uint64_t pageAddr_ = 0;

  uint64_t returnCycle_ = 0;

  bool completedReq_ = false;

  std::deque<std::pair<std::shared_ptr<reqEntry>,
                       std::vector<std::unique_ptr<MemPacket>>>>
      associatedPackets_ = {};
};

struct cacheMSHR {
  bool hasMissed_ = false;

  std::deque<std::shared_ptr<reqEntry>> associatedRequests_ = {};

  uint16_t assocPRFs_ = 0;

  uint64_t lastInteraction_ = 0;
};

class MMU {
 public:
  MMU(VAddrTranslator fn, std::function<void()> signalPFQClear);

  ~MMU() {}

  /** Tick the memory model to process the request queue. */
  void tick();

  /** Queue a read request. Returns true if there is space for the request.
   * Return false otherwise. */
  requestSuccess requestRead(const std::shared_ptr<Instruction>& uop);

  requestSuccess requestPrefetch(uint64_t vAddr, uint32_t size);

  /** Queue a write request. Returns true if there is space for the request.
   * Return false otherwise. */
  requestSuccess requestWrite(const std::shared_ptr<Instruction>& uop,
                              const std::vector<RegisterValue>& data);

  /** Process a write request of `data` to the target location that is not
   * associated to an instruction, or bound band bandwidth limits. */
  requestSuccess requestWrite(const std::shared_ptr<MemoryAccessTarget> target,
                              const RegisterValue& data,
                              bool bypassRestrictions = true);

  requestSuccess requestWrite(const MemoryAccessTarget& target,
                              const RegisterValue& data);

  /** Queue a read request from the supplied target location. This has zero
   * latency as instruction cache is not currently modelled. */
  void requestInstrRead(const MemoryAccessTarget& target);

  requestSuccess requestTranslation(const std::shared_ptr<Instruction>& uop);

  /** Retrieve all completed instruction read requests. */
  const span<MemoryReadResult> getCompletedInstrReads() const;

  /** Supply a virtual address translation that could not instantly be
   * retrieved. */
  void supplyDelayedTranslation(uint64_t vaddr, uint64_t paddr);

  /** Clear the completed instruction reads. */
  void clearCompletedIntrReads();

  /** Returns true if there are any oustanding memory requests in-flight. */
  bool hasPendingRequests() const;

  /** Method to set the TID for the MMU. */
  void setTid(uint64_t tid);

  uint64_t getTid();

  /** Function used to initialise the Data Port used for bidirection
   * communication. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initPort();

  uint64_t getNumDataReads() const { return numDataReads_; }
  uint64_t getNumDataWrites() const { return numDataWrites_; }
  uint64_t getNumInsnReads() const { return numInsnReads_; }
  // uint64_t getNumL1DTLBMisses() const { return numTLBMisses_; }
  // uint64_t getNumTLBMSHRBlocks() const { return numTLBMSHRBlocks_; }
  std::unordered_map<uint64_t, uint64_t> getNumInFlightRequestsTally_() const {
    return numInFlightRequestsTally_;
  }
  uint64_t getNumL1DDataMisses() const { return numCacheMisses_; }
  uint64_t getNumCacheMSHRBlocks() const { return numCacheMSHRBlocks_; }

  void enablePrint(bool enable) { print_ = enable; }

  bool hasActivePageFault() const {
    if (pendingRequests_.size()) return true;
    return false;
  }

  std::unordered_map<uint64_t, uint64_t> getLatMap() const { return latMap_; }

  void markMiss(uint64_t vAddr, uint8_t type);

  void notifyPrefetch(uint64_t paddr, uint64_t vaddr, uint64_t size);

 private:
  /** Process load or store requests. */
  void processRequests(uint8_t type);

  /** Method used to buffer data requests to memory. */
  void issueRequest(std::unique_ptr<MemPacket> request,
                    uint64_t delayedTranslation = -1);

  /** Returns true if unsigned overflow occurs. */
  bool unsignedOverflow(uint64_t a, uint64_t b) const {
    return (a + b) < a || (a + b) < b;
  }

  /** Check if given target crosses a cache line boundary. Returns true if no
   * cache line boundary is crossed. */
  bool isAligned(const MemoryAccessTarget& target) const;

  /** Splits a read memory access target into multiple MemPackets such that each
   * MemPacket is aligned w.r.t the cache line width and adds it to the output
   * vector.*/
  void createReadMemPackets(const MemoryAccessTarget& target,
                            std::vector<std::unique_ptr<MemPacket>>& outputVec,
                            const uint64_t insnSeqId, const uint16_t pktOrderId,
                            bool noResponse = false);

  /** Splits a write memory access target into multiple MemPackets such that
   * each MemPacket is aligned w.r.t the cache line width and adds it to the
   * output vector.*/
  void createWriteMemPackets(const MemoryAccessTarget& target,
                             std::vector<std::unique_ptr<MemPacket>>& outputVec,
                             const std::vector<char>& data,
                             const uint64_t insnSeqId,
                             const uint16_t pktOrderId);

  /** For a given instruction, supply all data from packets in readResponses_.
   */
  void supplyLoadInsnData(const uint64_t insnSeqId);

  /** A map containing all load instructions waiting for their results.
   * Key = Instruction sequenceID
   * Value = reqEntry struct */
  // std::map<uint64_t, reqEntry> requestedLoads_;
  // std::map<uint64_t, reqEntry> requestedTags_;

  /** Map containing all read response packets before they have been added to
   * their associated instruction.
   * Key = Instruction sequenceID
   * Value = map containing all responses for a specific instruction
   *            Key = packetOrderID
   *            Value = Vector of 1 or more packets, depending on if the request
   *                    was split */
  // std::map<uint64_t,
  //          std::map<uint16_t, std::vector<std::unique_ptr<MemPacket>>>>
  //     readResponses_;

  /** A map of virtual addresses to SimEng MemPacket objects helf whilst a
   * address translation is being retrieved asynchronously. */
  std::map<uint64_t, std::vector<std::unique_ptr<MemPacket>>> pendingRequests_;
  std::unordered_map<uint64_t, std::vector<std::shared_ptr<Instruction>>>
      pendingInsnRequests_;
  std::unordered_map<uint64_t, std::vector<std::shared_ptr<MemoryAccessTarget>>>
      pendingMemRequests_;

  /** A map containing all store instructions waiting for their results.
   * Key = Instruction sequenceID
   * Value = reqEntry struct */
  // std::map<uint64_t, reqEntry> requestedStores_;

  /** A vector containing all completed Instruction read requests. */
  std::vector<MemoryReadResult> completedInstrReads_;

  /** The number of pending data requests. */
  // uint64_t pendingDataRequests_ = 0;

  /** TID of the process currently communicating with this MMU. */
  uint64_t tid_ = 0;

  /** Size of a single cache line in bytes. */
  const uint64_t cacheLineWidth_;

  /** Fixed array containing vectors for all loads and store requests.
   * First in array contains all load requests for a number of instructions.
   * Each inner vector represents a single instruction.
   *
   * Second in array contains all store requests for a number of instructions.
   * Each inner vector represents a single instruction. */
  std::array<std::vector<std::vector<std::unique_ptr<MemPacket>>>, 2>
      loadsStores_;

  uint8_t numReqsInCycle_ = 0;
  uint8_t prfsInCycle = 0;
  uint16_t bandwidthUsed_ = 0;
  uint16_t prfBandwith = 0;

  // std::deque<uint64_t> tlbL1_;
  // uint16_t tlbL1Size_ = 16;
  // std::deque<tlbMSHR> tlbReqs_;
  // std::deque<uint64_t> tlbL2_;
  // uint64_t l2TLBmissPen_ = 8;
  // uint64_t maxL1TLBMSHRs_ = 8;
  // uint64_t activeTLBMSHRs_ = 0;
  // uint64_t numTLBMisses_ = 0;
  // uint64_t numTLBMSHRBlocks_ = 0;

  std::unordered_map<uint64_t, cacheMSHR> l1MSHRs_;
  uint64_t moBufferSize_ = 4;
  uint64_t uniqueActiveMSHRs_ = 0;
  uint64_t miBufferSize_ = 43;
  uint64_t totalActiveMSHRs_ = 0;
  uint64_t assumedCacheMissedCycles_ = 46;
  uint64_t numCacheMisses_ = 0;
  uint64_t numCacheMSHRBlocks_ = 0;

  std::deque<std::shared_ptr<reqEntry>> inFlightRequests_;
  std::unordered_map<uint64_t, uint64_t> numInFlightRequestsTally_;
  std::unordered_map<
      uint64_t, std::map<uint16_t, std::vector<std::unique_ptr<MemPacket>>>>
      readResponses_ = {};
  std::unordered_map<uint64_t, uint64_t> latMap_;

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

  std::function<void()> signalPFQClear_;

  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> port_ = nullptr;

  uint64_t numDataReads_ = 0;
  uint64_t numInsnReads_ = 0;
  uint64_t numDataWrites_ = 0;

  uint64_t ticks_ = 0;

  uint64_t packetIds_ = 0;
  uint64_t reqIds_ = 0;

  bool print_ = false;
};

}  // namespace memory
}  // namespace simeng
