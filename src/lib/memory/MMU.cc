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
                      const uint64_t requestId, bool isReserved) {
  pendingDataRequests_++;
  std::unique_ptr<memory::MemPacket> req = memory::MemPacket::createReadRequest(
      target.vaddr, target.size, requestId);
  if (isReserved) req->markAsResLoad();
  bufferRequest(std::move(req));
}

void MMU::requestWrite(const MemoryAccessTarget& target,
                       const RegisterValue& data, const uint64_t requestId,
                       bool isConditional) {
  pendingDataRequests_++;
  const char* wdata = data.getAsVector<char>();
  std::vector<char> dt(wdata, wdata + target.size);
  std::unique_ptr<MemPacket> req =
      MemPacket::createWriteRequest(target.vaddr, target.size, requestId, dt);
  if (isConditional) req->markAsCondStore();
  bufferRequest(std::move(req));
}

void MMU::requestInstrRead(const MemoryAccessTarget& target,
                           uint64_t requestId) {
  std::unique_ptr<memory::MemPacket> insRequest =
      memory::MemPacket::createReadRequest(target.vaddr, target.size,
                                           requestId);
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
    // If Load-Reserved, add new Monitor for cache line
    if (request->isResLoad()) {
      cacheLineMonitor_.push_back(downAlign(paddr, cacheLineWidth_));
    } else if (request->isCondStore()) {
      // If monitor exists, clear it and proceed. Else, fail store
      auto itr =
          std::find(cacheLineMonitor_.begin(), cacheLineMonitor_.end(), paddr);
      if (itr != cacheLineMonitor_.end()) {
        cacheLineMonitor_.erase(itr);
      } else {
        request->markAsIgnored();
      }
    } else if (request->isWrite()) {
      // Check if write requests overlaps any open cache line monitors. If yes,
      // remove monitors to invalidate them.
      uint64_t clStart = downAlign(paddr, cacheLineWidth_);
      // Unaligned requests could cover 2 cache lines
      uint64_t clEnd = downAlign(paddr + request->size_, cacheLineWidth_);
      auto itr = std::find(cacheLineMonitor_.begin(), cacheLineMonitor_.end(),
                           clStart);
      if (itr != cacheLineMonitor_.end()) {
        cacheLineMonitor_.erase(itr);
      }
      if (clStart != clEnd) {
        itr = std::find(cacheLineMonitor_.begin(), cacheLineMonitor_.end(),
                        clEnd);
        if (itr != cacheLineMonitor_.end()) {
          cacheLineMonitor_.erase(itr);
        }
      }
    }
  }

  port_->send(std::move(request));
}

void MMU::setTid(uint64_t tid) {
  tid_ = tid;
  // TID only updated on context switch, must clear cache line monitor
  cacheLineMonitor_.clear();
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
      // TODO update when global monitor / atomics support added.
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
