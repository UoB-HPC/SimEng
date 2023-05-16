#include "simeng/memory/MMU.hh"

#include <algorithm>
#include <cstdint>
#include <memory>

namespace simeng {
namespace memory {

MMU::MMU(VAddrTranslator fn)
    : cacheLineWidth_(
          Config::get()["Memory-Hierarchy"]["Cache-Line-Width"].as<uint64_t>()),
      translate_(fn) {}

void MMU::requestRead(const std::shared_ptr<Instruction>& uop) {
  uint64_t requestId = uop->getSequenceId();
  uint64_t instructionID = uop->getInstructionId();
  bool isReserved = uop->isLoadReserved();
  // Register load in map
  requestedLoads_[requestId] = uop;

  // Generate and fire off requests
  const auto& targets = uop->getGeneratedAddresses();
  for (auto& target : targets) {
    pendingDataRequests_++;
    std::unique_ptr<memory::MemPacket> req =
        memory::MemPacket::createReadRequest(target.vaddr, target.size,
                                             requestId, instructionID);
    if (isReserved) req->markAsResLoad();
    bufferRequest(std::move(req));
  }
}

void MMU::requestWrite(const std::shared_ptr<Instruction>& uop,
                       const std::vector<RegisterValue>& data) {
  uint64_t requestId = uop->getSequenceId();
  uint64_t instructionID = uop->getInstructionId();
  bool isConditional = uop->isStoreCond();

  // Register conditional store in map
  if (isConditional) requestedCondStore_[requestId] = uop;

  // Create and fire off requests
  const auto& targets = uop->getGeneratedAddresses();
  assert(data.size() == targets.size() &&
         "[SimEng:MMU] Number of addresses does not match the number of data "
         "elements to write.");
  for (int i = 0; i < targets.size(); i++) {
    pendingDataRequests_++;
    const auto& target = targets[i];
    const char* wdata = data[i].getAsVector<char>();
    std::vector<char> dt(wdata, wdata + target.size);
    std::unique_ptr<MemPacket> req = MemPacket::createWriteRequest(
        target.vaddr, target.size, requestId, instructionID, dt);
    if (isConditional) req->markAsCondStore();
    bufferRequest(std::move(req));
  }
}

void MMU::requestWrite(const MemoryAccessTarget& target,
                       const RegisterValue& data) {
  // Create and fire off request
  pendingDataRequests_++;
  const char* wdata = data.getAsVector<char>();
  std::vector<char> dt(wdata, wdata + target.size);
  std::unique_ptr<MemPacket> req =
      MemPacket::createWriteRequest(target.vaddr, target.size, 0, 0, dt);
  bufferRequest(std::move(req));
}

void MMU::requestInstrRead(const MemoryAccessTarget& target) {
  // Create and fire off request
  std::unique_ptr<memory::MemPacket> insRequest =
      memory::MemPacket::createReadRequest(target.vaddr, target.size, 0, 0);
  insRequest->markAsUntimed();
  insRequest->markAsInstrRead();
  bufferRequest(std::move(insRequest));
}

const span<MemoryReadResult> MMU::getCompletedInstrReads() const {
  return {const_cast<MemoryReadResult*>(completedInstrReads_.data()),
          completedInstrReads_.size()};
}

void MMU::clearCompletedIntrReads() { completedInstrReads_.clear(); }

bool MMU::hasPendingRequests() const { return pendingDataRequests_ != 0; }

void MMU::bufferRequest(std::unique_ptr<MemPacket> request) {
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
    if (!request->isInstrRead()) updateLLSCMonitor(request);
  }

  port_->send(std::move(request));
}

void MMU::setTid(uint64_t tid) {
  tid_ = tid;
  // TID only updated on context switch, must clear cache line monitor
  cacheLineMonitor_.second = false;
}

/** NOTE: Assumes all Load-Reserved & Store-Conditional accesses are aligned. */
void MMU::updateLLSCMonitor(const std::unique_ptr<MemPacket>& request) {
  // If Load-Reserved, add Monitored cache line.
  if (request->isResLoad()) {
    cacheLineMonitor_ = {downAlign(request->paddr_, cacheLineWidth_), true};
  } else if (request->isCondStore()) {
    // See if monitor is valid
    if (cacheLineMonitor_.second) {
      // See if cache lines match, if yes, remove monitor and proceed
      if (downAlign(request->paddr_, cacheLineWidth_) ==
          cacheLineMonitor_.first) {
        cacheLineMonitor_.second = false;
      } else {
        // If no match, fail condStore
        request->markAsIgnored();
      }
    } else {
      // If not valid, fail condStore
      request->markAsIgnored();
    }
  } else if (request->isWrite()) {
    // Check if write requests overlaps the cache line monitor. If yes,
    // remove monitors to invalidate it.
    if (downAlign(request->paddr_, cacheLineWidth_) ==
            cacheLineMonitor_.first ||
        downAlign(request->paddr_ + request->size_, cacheLineWidth_) ==
            cacheLineMonitor_.first) {
      cacheLineMonitor_.second = false;
    }
  }
}

std::shared_ptr<Port<std::unique_ptr<MemPacket>>> MMU::initPort() {
  port_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    if (packet->isInstrRead()) {
      if (packet->isFaulty() || packet->ignore()) {
        // If faulty or ignored, return no data. This signals a data abort.
        completedInstrReads_.push_back(
            {{packet->vaddr_, packet->size_}, RegisterValue(), packet->id_});
        return;
      }
      completedInstrReads_.push_back(
          {{packet->vaddr_, packet->size_},
           RegisterValue(packet->payload().data(), packet->size_),
           packet->id_});
      return;
    }

    pendingDataRequests_--;
    if (packet->isRead()) {
      const auto& insn = requestedLoads_.find(packet->id_);
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
    if (packet->isCondStore()) {
      // Assumes one response per instruction.
      bool success = true;
      if (packet->isFaulty() || packet->ignore()) {
        success = false;
      }
      const auto& insn = requestedCondStore_.find(packet->id_);
      assert(insn != requestedCondStore_.end() &&
             "[SimEng:MMU] Tried to supply result to a conditional store that "
             "isn't in the completedCondStores_ map.");
      insn->second->updateCondStoreResult(success);
      // Conditonal store now has result. Remove from map
      requestedCondStore_.erase(insn);
    }
  };
  port_->registerReceiver(fn);
  return port_;
}

}  // namespace memory
}  // namespace simeng
