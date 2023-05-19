#include "simeng/memory/MMU.hh"

#include <algorithm>
#include <cstdint>
#include <memory>

namespace simeng {
namespace memory {

MMU::MMU(VAddrTranslator fn)
    : cacheLineWidth_(
          Config::get()["Memory-Hierarchy"]["Cache-Line-Width"].as<uint64_t>()),
      translate_(fn) {
  // Initialise Memory bandwidth and request limits
  // TODO: replace with cleaner solution in the ModelConfig itself
  if (Config::get()["Core"]["Simulation-Mode"].as<std::string>() !=
      "emulation") {
    loadBandwidth_ =
        Config::get()["LSQ-Memory-Interface"]["Load-Bandwidth"].as<uint64_t>();
    storeBandwidth_ =
        Config::get()["LSQ-Memory-Interface"]["Store-Bandwidth"].as<uint64_t>();
    requestLimit_ =
        Config::get()["LSQ-Memory-Interface"]["Permitted-Requests-Per-Cycle"]
            .as<uint64_t>();
    loadRequestLimit_ =
        Config::get()["LSQ-Memory-Interface"]["Permitted-Loads-Per-Cycle"]
            .as<uint64_t>();
    storeRequestLimit_ =
        Config::get()["LSQ-Memory-Interface"]["Permitted-Stores-Per-Cycle"]
            .as<uint64_t>();
    exclusiveRequests_ =
        Config::get()["LSQ-Memory-Interface"]["Exclusive"].as<bool>();
  } else {
    // If core model is emulation, remove all bandwidth and request limits. This
    // ensures single cycle processing of each instruction.
    loadBandwidth_ = UINT64_MAX;
    storeBandwidth_ = UINT64_MAX;
    requestLimit_ = UINT64_MAX;
    loadRequestLimit_ = UINT64_MAX;
    storeRequestLimit_ = UINT64_MAX;
    exclusiveRequests_ = true;
  }
}

void MMU::tick() {
  /** NOTE: The number of instructions present in each of the load / store
   * vectors is limited inside the `requestRead()` and `requestWrite()`
   * functions when we add to these vectors.
   * - Total instructions across loads and stores will equal (at most) to
   *   requestLimit_.
   * - Total loads will not exceed loadRequestLimit_.
   * - Total stores will not exceed storeRequestLimit_.
   * - If exclusiveRequests_ == true, then there will only be stores or loads
   *   at any one time. */
  if (exclusiveRequests_) {
    // If exclusive access, see which access type has available instructions.
    bool isStore = loadsStores_[STR].size() != 0;
    processRequests(isStore);
  } else {
    // Process Stores first (same as LSQ)
    processRequests(STR);
    processRequests(LD);
  }
}

void MMU::processRequests(const bool isStore) {
  uint64_t bandwidthLimit = isStore ? storeBandwidth_ : loadBandwidth_;
  uint64_t bandwidthUsed = 0;
  while (loadsStores_[isStore].size() > 0) {
    auto insn = loadsStores_[isStore].begin();
    // Process as many requests as possible within bandwidth limit
    auto pkt = insn->begin();
    while (pkt != insn->end()) {
      // Check that sending this packet won't exceed bandwidth
      if ((bandwidthUsed + (*pkt)->size_) <= bandwidthLimit) {
        bandwidthUsed += (*pkt)->size_;
        issueRequest(std::move(*pkt));
        pkt = insn->erase(pkt);
      } else {
        // Bandwidth will be exceeded. Stop sending instruction packets
        return;
      }
    }
    // If insn is now empty (all requests have been sent) then remove it
    // from the vector
    if (insn->size() == 0) {
      loadsStores_[isStore].erase(insn);
    }
  }
}

bool MMU::requestRead(const std::shared_ptr<Instruction>& uop) {
  // Check if space for instruction
  // If exclusive then no loads permitted if store still being processed
  if (exclusiveRequests_ && (loadsStores_[STR].size() != 0)) return false;
  // Check total limit isn't met if not exclusive
  if (!exclusiveRequests_ &&
      (loadsStores_[LD].size() + loadsStores_[STR].size() == requestLimit_))
    return false;
  // Check space left for a load
  if (loadsStores_[LD].size() == loadRequestLimit_) return false;

  uint64_t seqId = uop->getSequenceId();

  // Check if new cacheLineMonitor needs to be opened
  if (uop->isLoadReserved()) {
    openLLSCMonitor(uop);
  }

  // Register load in map
  requestedLoads_[seqId] = uop;

  // Initialise space in loads
  loadsStores_[LD].push_back({});
  // Generate and fire off requests
  const auto& targets = uop->getGeneratedAddresses();
  for (auto& target : targets) {
    pendingDataRequests_++;
    std::unique_ptr<memory::MemPacket> req =
        memory::MemPacket::createReadRequest(target.vaddr, target.size, seqId);
    loadsStores_[LD].back().push_back(std::move(req));
  }
  return true;
}

bool MMU::requestWrite(const std::shared_ptr<Instruction>& uop,
                       const std::vector<RegisterValue>& data) {
  // Check if space for instruction
  // If exclusive then no stores permitted if load still being processed
  if (exclusiveRequests_ && (loadsStores_[LD].size() != 0)) return false;
  // Check total limit isn't met if not exclusive
  if (!exclusiveRequests_ &&
      (loadsStores_[LD].size() + loadsStores_[STR].size() == requestLimit_))
    return false;
  // Check space left for a store
  if (loadsStores_[STR].size() == storeRequestLimit_) return false;

  bool isConditional = uop->isStoreCond();
  if (isConditional) {
    if (checkLLSCMonitor(uop) == false) {
      // No valid monitor, fail store
      uop->updateCondStoreResult(false);
      return true;
    } else {
      uop->updateCondStoreResult(true);
    }
  }

  // Initialise space in stores
  loadsStores_[STR].push_back({});
  // Create and fire off requests
  const auto& targets = uop->getGeneratedAddresses();
  uint64_t seqId = uop->getSequenceId();
  assert(data.size() == targets.size() &&
         "[SimEng:MMU] Number of addresses does not match the number of data "
         "elements to write.");
  for (int i = 0; i < targets.size(); i++) {
    pendingDataRequests_++;
    const auto& target = targets[i];
    const char* wdata = data[i].getAsVector<char>();
    std::vector<char> dt(wdata, wdata + target.size);
    std::unique_ptr<MemPacket> req =
        MemPacket::createWriteRequest(target.vaddr, target.size, seqId, dt);
    if (!isConditional) updateLLSCMonitor(target);
    loadsStores_[STR].back().push_back(std::move(req));
  }
  return true;
}

void MMU::requestWrite(const MemoryAccessTarget& target,
                       const RegisterValue& data) {
  // Create and fire off request
  pendingDataRequests_++;
  const char* wdata = data.getAsVector<char>();
  std::vector<char> dt(wdata, wdata + target.size);
  std::unique_ptr<MemPacket> req =
      MemPacket::createWriteRequest(target.vaddr, target.size, 0, dt);
  updateLLSCMonitor(target);
  issueRequest(std::move(req));
}

void MMU::requestInstrRead(const MemoryAccessTarget& target) {
  // Create and fire off request
  std::unique_ptr<memory::MemPacket> insRequest =
      memory::MemPacket::createReadRequest(target.vaddr, target.size, 0);
  insRequest->markAsUntimed();
  insRequest->markAsInstrRead();
  issueRequest(std::move(insRequest));
}

const span<MemoryReadResult> MMU::getCompletedInstrReads() const {
  return {const_cast<MemoryReadResult*>(completedInstrReads_.data()),
          completedInstrReads_.size()};
}

void MMU::clearCompletedIntrReads() { completedInstrReads_.clear(); }

bool MMU::hasPendingRequests() const { return pendingDataRequests_ != 0; }

void MMU::setTid(uint64_t tid) {
  tid_ = tid;
  // TID only updated on context switch, must clear cache line monitor
  cacheLineMonitor_.second = false;
}

std::shared_ptr<Port<std::unique_ptr<MemPacket>>> MMU::initPort() {
  port_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    if (packet->isInstrRead()) {
      if (packet->isFaulty() || packet->ignore()) {
        // If faulty or ignored, return no data. This signals a data abort.
        completedInstrReads_.push_back({{packet->vaddr_, packet->size_},
                                        RegisterValue(),
                                        packet->insnSeqId_});
        return;
      }
      completedInstrReads_.push_back(
          {{packet->vaddr_, packet->size_},
           RegisterValue(packet->payload().data(), packet->size_),
           packet->insnSeqId_});
      return;
    }

    pendingDataRequests_--;
    if (packet->isRead()) {
      const auto& insn = requestedLoads_.find(packet->insnSeqId_);
      assert(insn != requestedLoads_.end() &&
             "[SimEng:MMU] Tried to supply result to a load instruction that "
             "isn't in the requestedLoads_ map.");
      if (packet->isFaulty()) {
        // If faulty, return no data. This signals a data abort.
        insn->second->supplyData(packet->vaddr_, RegisterValue());
      } else {
        insn->second->supplyData(packet->vaddr_,
                                 {packet->payload().data(), packet->size_});
      }
      // If instruction has all data, remove from requestedLoads_ map
      if (insn->second->hasAllData()) {
        requestedLoads_.erase(insn);
      }
    }
  };
  port_->registerReceiver(fn);
  return port_;
}

void MMU::issueRequest(std::unique_ptr<MemPacket> request) {
  // Since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  uint64_t paddr = translate_(request->vaddr_, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);

  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    request->markAsFaulty();
    port_->recieve(std::move(request));
    return;
  }

  if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    request->markAsIgnored();
  } else {
    request->paddr_ = paddr;
  }

  port_->send(std::move(request));
}

void MMU::openLLSCMonitor(const std::shared_ptr<Instruction>& loadRes) {
  assert(loadRes->isLoadReserved() &&
         "[SimEng:MMU] Cannot open an LL/SC monitor with a non-load-reserved "
         "instruction.");
  // For each target, extract which cache lines they are contained within
  cacheLineMonitor_ = {{}, true};
  const auto& targets = loadRes->getGeneratedAddresses();
  // We can use Vaddr for LL/SC monitor given that a) monitors are unique to a
  // thread, and b) all addresses within the same cache line will have the
  // same upper (64-log2(cacheLineWidth))-bits, which is the resolution we are
  // aligning to also
  for (auto& target : targets) {
    // Add cache lines to set. Assumes access is unaligned, but in the case it
    // is aligned the use of a std::set ensures uniqueness of elements.
    cacheLineMonitor_.first.emplace(downAlign(target.vaddr, cacheLineWidth_));
    cacheLineMonitor_.first.emplace(
        downAlign(target.vaddr + target.size, cacheLineWidth_));
  }
}

bool MMU::checkLLSCMonitor(const std::shared_ptr<Instruction>& strCond) {
  assert(strCond->isStoreCond() &&
         "[SimEng:MMU] Can only check a cache line monitor with a "
         "store-conditional instruction.");
  if (cacheLineMonitor_.second == false) {
    return false;
  }
  // For each target, check whether it is contained within the monitored region
  const auto& targets = strCond->getGeneratedAddresses();
  for (auto& target : targets) {
    // Assume unaligned access, need to check both possible cache lines
    if (cacheLineMonitor_.first.count(
            downAlign(target.vaddr, cacheLineWidth_)) == 0) {
      // Not in monitored region, fail
      return false;
    }
    if (cacheLineMonitor_.first.count(
            downAlign(target.vaddr + target.size, cacheLineWidth_)) == 0) {
      // Not in monitored region, fail
      return false;
    }
  }
  // All targets within monitor, return true to proceed with conditional store
  // and invalidate monitor
  cacheLineMonitor_.second = false;
  return true;
}

void MMU::updateLLSCMonitor(const MemoryAccessTarget& storeTarget) {
  if (cacheLineMonitor_.second == true) {
    // Assume unaligned access, need to check both possible cache lines
    if (cacheLineMonitor_.first.count(
            downAlign(storeTarget.vaddr, cacheLineWidth_)) == 1) {
      // In monitored region, invalidate monitor
      cacheLineMonitor_.second = false;
      return;
    }
    if (cacheLineMonitor_.first.count(downAlign(
            storeTarget.vaddr + storeTarget.size, cacheLineWidth_)) == 1) {
      // In monitored region, invalidate monitor
      cacheLineMonitor_.second = false;
      return;
    }
  }
}

}  // namespace memory
}  // namespace simeng
