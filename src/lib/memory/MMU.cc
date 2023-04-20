#include "simeng/memory/MMU.hh"

#include <cstdint>
#include <memory>

namespace simeng {
namespace memory {

MMU::MMU(const uint16_t latency, VAddrTranslator fn)
    : latency_(latency), translate_(fn) {}

void MMU::tick() {
  tickCounter_++;

  while (pendingRequests_.size() > 0) {
    const auto& request = pendingRequests_.front();

    if (request.readyAt > tickCounter_) {
      // Head of queue isn't ready yet; end cycle
      break;
    }

    const auto& target = request.target;
    uint64_t requestId = request.requestId;

    if (request.write) {
      const char* wdata = request.data.getAsVector<char>();
      std::vector<char> dt(wdata, wdata + target.size);
      bufferRequest(memory::MemPacket::createWriteRequest(
          target.address, target.size, requestId, dt));
    } else {
      bufferRequest(memory::MemPacket::createReadRequest(
          target.address, target.size, requestId));
    }

    // Remove the request from the queue
    pendingRequests_.pop();
  }
}

void MMU::requestRead(const MemoryAccessTarget& target,
                      const uint64_t requestId) {
  pendingRequests_.push({target, tickCounter_ + latency_, requestId});
}

void MMU::requestWrite(const MemoryAccessTarget& target,
                       const RegisterValue& data, const uint64_t requestId) {
  pendingRequests_.push({target, data, tickCounter_ + latency_, requestId});
}

void MMU::requestInstrRead(const MemoryAccessTarget& target,
                           const uint64_t requestId) {
  uint64_t paddr = translate_(target.address, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);

  std::unique_ptr<memory::MemPacket> pkt = memory::MemPacket::createReadRequest(
      target.address, target.size, requestId);
  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    port_->recieve(MemPacket::createFaultyMemPacket());
    return;
  } else if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    pkt->setIgnored();
  } else {
    pkt->paddr_ = paddr;
    pkt->setUntimedRead();
  }
  port_->send(std::move(pkt));
}

const span<MemoryReadResult> MMU::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

const span<MemoryReadResult> MMU::getCompletedInstrReads() const {
  return {const_cast<MemoryReadResult*>(completedInstrReads_.data()),
          completedInstrReads_.size()};
}

void MMU::clearCompletedReads() { completedReads_.clear(); }

void MMU::clearCompletedIntrReads() { completedInstrReads_.clear(); }

bool MMU::hasPendingRequests() const { return !pendingRequests_.empty(); }

void MMU::bufferRequest(std::unique_ptr<MemPacket> request) {
  // Since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  uint64_t paddr = translate_(request->vaddr_, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);

  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    port_->recieve(MemPacket::createFaultyMemPacket());
    return;
  } else if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    request->setIgnored();
  } else {
    request->paddr_ = paddr;
  }
  port_->send(std::move(request));
}

void MMU::setTid(uint64_t tid) { tid_ = tid; }

Port<std::unique_ptr<MemPacket>>* MMU::initPort() {
  port_ = new Port<std::unique_ptr<MemPacket>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    if (packet->isUntimedRead()) {
      // Untimed Read only used by instruction requests
      if (packet->isFaulty()) {
        // If faulty, return no data. This signals a data abort.
        completedInstrReads_.push_back(
            // Risky cast from uint64_t to uint8_t due to MemoryAccessTarget
            // definition
            {{packet->vaddr_, static_cast<uint8_t>(packet->size_), packet->id_},
             RegisterValue(),
             packet->id_});
        return;
      }
      completedInstrReads_.push_back(
          // Risky cast from uint64_t to uint8_t due to MemoryAccessTarget
          // definition
          {{packet->vaddr_, static_cast<uint8_t>(packet->size_), packet->id_},
           RegisterValue(packet->data().data(), packet->size_),
           packet->id_});
      return;
    }

    if (packet->isRead()) {
      if (packet->isFaulty()) {
        // If faulty, return no data. This signals a data abort.
        completedReads_.push_back(
            // Risky cast from uint64_t to uint8_t due to MemoryAccessTarget
            // definition
            {{packet->vaddr_, static_cast<uint8_t>(packet->size_), packet->id_},
             RegisterValue(),
             packet->id_});
        return;
      }
      completedReads_.push_back(
          // Risky cast from uint64_t to uint8_t due to MemoryAccessTarget
          // definition
          {{packet->vaddr_, static_cast<uint8_t>(packet->size_), packet->id_},
           RegisterValue(packet->data().data(), packet->size_),
           packet->id_});
    }
  };
  port_->registerReceiver(fn);
  return port_;
}

}  // namespace memory
}  // namespace simeng
