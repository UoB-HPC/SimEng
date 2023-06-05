#include "simeng/memory/MMU.hh"

#include <algorithm>
#include <cstdint>
#include <memory>

namespace simeng {
namespace memory {

MMU::MMU(VAddrTranslator fn) : translate_(fn) {}

void MMU::requestRead(const MemoryAccessTarget& target,
                      const uint64_t requestId) {
  pendingDataRequests_++;
  bufferRequest(memory::MemPacket::createReadRequest(target.vaddr, target.size,
                                                     requestId));
}

void MMU::requestWrite(const MemoryAccessTarget& target,
                       const RegisterValue& data, const uint64_t requestId) {
  pendingDataRequests_++;
  const char* wdata = data.getAsVector<char>();
  std::vector<char> dt(wdata, wdata + target.size);
  bufferRequest(memory::MemPacket::createWriteRequest(target.vaddr, target.size,
                                                      requestId, dt));
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

void MMU::handleIgnoredRequest(std::unique_ptr<MemPacket>& pkt) {
  if (pkt->isRead()) {
    pkt->turnIntoReadResponse(std::vector<char>(pkt->size_, '\0'));
  } else {
    pkt->payload().clear();
    pkt->turnIntoWriteResponse();
  }
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
  }

  request->paddr_ = paddr;
  port_->send(std::move(request));
}

void MMU::setTid(uint64_t tid) { tid_ = tid; }

std::shared_ptr<Port<CPUMemoryPacket>> MMU::initDataPort() {
  port_ = std::make_shared<Port<CPUMemoryPacket>>();
  auto fn = [this](CPUMemoryPacket packet) -> void {
    /**
  if (packet->isUntimedRead()) {
    // Untimed Read only used by instruction requests
    if (packet->isFaulty()) {
      // If faulty, return no data. This signals a data abort.
      completedInstrReads_.push_back(
          {{packet->vaddr_, packet->size_}, RegisterValue(), packet->id_});
      return;
    }
    completedInstrReads_.push_back(
        // Risky cast from uint64_t to uint8_t due to MemoryAccessTarget
        // definition
        {{packet->vaddr_, packet->size_},
         RegisterValue(packet->payload().data(), packet->size_),
         packet->id_});
    return;
  }
  */
    if (packet.type_ == MemoryAccessType::READ) {
      completedReads_.push_back(
          {{packet.vaddr_, packet.size_},
           RegisterValue(packet.payload_.data(), packet.size_),
           packet.id_});
    }
    // Currently, ignore write responses.
  };
  port_->registerReceiver(fn);
  return port_;
}

std::shared_ptr<Port<CPUMemoryPacket>> MMU::initUntimedInstrReadPort() {
  untimedInstrReadPort_ = std::make_shared<Port<CPUMemoryPacket>>();
  auto fn = [this](CPUMemoryPacket packet) -> void {
    completedInstrReads_.push_back(
        {{packet.vaddr_, packet.size_},
         RegisterValue(packet.payload_.data(), packet.size_),
         packet.id_});
  };
  port_->registerReceiver(fn);
  return port_;
}

}  // namespace memory
}  // namespace simeng
