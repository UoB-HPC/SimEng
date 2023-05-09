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

void MMU::requestRead(const MemoryAccessTarget& target,
                      const uint64_t requestId, const uint64_t instructionID,
                      bool isReserved) {
  pendingDataRequests_++;
  std::unique_ptr<memory::MemPacket> req = memory::MemPacket::createReadRequest(
      target.vaddr, target.size, requestId, instructionID);
  if (isReserved) req->markAsResLoad();
  bufferRequest(std::move(req));
}

void MMU::requestWrite(const MemoryAccessTarget& target,
                       const RegisterValue& data, const uint64_t requestId,
                       const uint64_t instructionID, bool isConditional) {
  pendingDataRequests_++;
  const char* wdata = data.getAsVector<char>();
  std::vector<char> dt(wdata, wdata + target.size);
  std::unique_ptr<MemPacket> req = MemPacket::createWriteRequest(
      target.vaddr, target.size, requestId, instructionID, dt);
  if (isConditional) req->markAsCondStore();
  bufferRequest(std::move(req));
}

void MMU::requestInstrRead(const MemoryAccessTarget& target,
                           const uint64_t requestId,
                           const uint64_t instructionID) {
  std::unique_ptr<memory::MemPacket> insRequest =
      memory::MemPacket::createReadRequest(target.vaddr, target.size, requestId,
                                           instructionID);
  insRequest->markAsUntimed();
  insRequest->markAsInstrRead();
  bufferRequest(std::move(insRequest));
}

const span<MemoryReadResult> MMU::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

const span<MemoryReadResult> MMU::getCompletedInstrReads() const {
  return {const_cast<MemoryReadResult*>(completedInstrReads_.data()),
          completedInstrReads_.size()};
}

const span<CondStoreResult> MMU::getCompletedCondStores() const {
  return {const_cast<CondStoreResult*>(completedCondStores_.data()),
          completedCondStores_.size()};
}

void MMU::clearCompletedReads() { completedReads_.clear(); }

void MMU::clearCompletedIntrReads() { completedInstrReads_.clear(); }

void MMU::clearCompletedCondStores() { completedCondStores_.clear(); }

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
  cacheLineMonitor_.clear();
}

/** NOTE: Assumes all Load-Reserved & Store-Conditional accesses are aligned. */
void MMU::updateLLSCMonitor(const std::unique_ptr<MemPacket>& request) {
  // If Load-Reserved, add Monitored cache line.
  if (request->isResLoad()) {
    cacheLineMonitor_.emplace(request->insnId_,
                              downAlign(request->paddr_, cacheLineWidth_));
  } else if (request->isCondStore()) {
    // Find first insnID GT condStore (filter out monitors opened by speculated
    // instructions)
    auto itr = cacheLineMonitor_.upper_bound(request->insnId_);
    // We know that the previous monitor to this is our valid monitor
    if (itr == cacheLineMonitor_.begin()) {
      // If first monitor in map is GT condStore, no valid monitor exists
      request->markAsIgnored();
    } else {
      // Get previous monitor
      itr--;
      // See if cache lines match, if yes, remove monitor and proceed
      if (downAlign(request->paddr_, cacheLineWidth_) == itr->second) {
        cacheLineMonitor_.clear();
      } else {
        // If no match, fail condStore
        request->markAsIgnored();
      }
    }
  } else if (request->isWrite()) {
    // Find first insnID GT condStore (filter out monitors opened by speculated
    // instructions)
    auto itr = cacheLineMonitor_.upper_bound(request->insnId_);
    // We know that the previous monitor to this is our valid monitor
    if (itr != cacheLineMonitor_.begin()) {
      itr--;
      // Check if write requests overlaps the cache line monitor. If yes,
      // remove monitors to invalidate it.
      if (downAlign(request->paddr_, cacheLineWidth_) == itr->second ||
          downAlign(request->paddr_ + request->size_, cacheLineWidth_) ==
              itr->second) {
        cacheLineMonitor_.clear();
      }
    }
  }
}

void MMU::flushLLSCMonitor(const uint64_t instructionID) {
  // Find first entry >= instructionID
  auto itr = cacheLineMonitor_.lower_bound(instructionID);
  // Remove all entries from itr to end of map
  while (itr != cacheLineMonitor_.end()) {
    itr = cacheLineMonitor_.erase(itr);
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
      if (packet->isFaulty()) {
        // If faulty, return no data. This signals a data abort.
        completedReads_.push_back(
            {{packet->vaddr_, packet->size_}, RegisterValue(), packet->id_});
        return;
      }
      completedReads_.push_back(
          {{packet->vaddr_, packet->size_},
           RegisterValue(packet->payload().data(), packet->size_),
           packet->id_});
    }
    if (packet->isCondStore()) {
      bool success = true;
      if (packet->isFaulty() || packet->ignore()) {
        success = false;
      }
      completedCondStores_.push_back({packet->id_, success});
    }
  };
  port_->registerReceiver(fn);
  return port_;
}

}  // namespace memory
}  // namespace simeng
