#include "simeng/memory/MMU.hh"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

#include "simeng/OS/Constants.hh"
#include "simeng/RegisterValue.hh"
#include "simeng/memory/MemPacket.hh"

namespace simeng {
namespace memory {

MMU::MMU(VAddrTranslator fn) : translate_(fn) {}

void MMU::requestRead(const MemoryAccessTarget& target,
                      const uint64_t requestId) {
  pendingDataRequests_++;
  bufferRequest(target, requestId);
}

void MMU::requestWrite(const MemoryAccessTarget& target,
                       const RegisterValue& data, const uint64_t requestId) {
  pendingDataRequests_++;
  bufferRequest(target, requestId);
}

void MMU::requestInstrRead(const MemoryAccessTarget& target,
                           uint64_t requestId) {
  uint64_t paddr = translate_(target.vaddr, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);
  if (!faultCode) {
    untimedInstrReadPort_->send(CPUMemoryPacket(MemoryAccessType::READ,
                                                target.vaddr, paddr,
                                                target.size, requestId, 0, 0));
  } else if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    completedInstrReads_.push_back(
        {{target.vaddr, target.size}, RegisterValue(), requestId});
  } else if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    std::vector<char> data(target.size, '\0');
    completedInstrReads_.push_back({{target.vaddr, target.size},
                                    RegisterValue(data.data(), target.size),
                                    requestId});
  }
}

void MMU::handleTranslationFaultForDataReqs(uint64_t faultCode,
                                            const MemoryAccessTarget& target,
                                            const uint64_t requestId) {}

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

void MMU::bufferRequest(const MemoryAccessTarget& target,
                        const uint64_t requestId) {
  // Since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  uint64_t paddr = translate_(target.vaddr, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);
  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    completedInstrReads_.push_back(
        {{target.vaddr, target.size}, RegisterValue(), requestId});
    return;
  }

  if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    std::vector<char> data(target.size, '\0');
    completedReads_.push_back({{target.vaddr, target.size},
                               RegisterValue(data.data(), target.size),
                               requestId});
    return;
  }
  auto cpuPkt = CPUMemoryPacket(MemoryAccessType::READ, target.vaddr, paddr,
                                target.size, requestId, 0, 0);

  port_->send(cpuPkt);
}

void MMU::bufferRequest(const MemoryAccessTarget& target,
                        const uint64_t requestId,
                        const RegisterValue& payload) {
  // Since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  uint64_t paddr = translate_(target.vaddr, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);
  // Write requests in SimEng cannot result in a DATA_ABORT because SimEng
  // doesn't do writes speculatively. As far ignored write requests are
  // concerned we ignore them by returning early.
  if (faultCode) return;

  auto cpuPkt = CPUMemoryPacket(MemoryAccessType::WRITE, target.vaddr, paddr,
                                target.size, requestId, 0, 0);
  cpuPkt.payload_ = std::vector<char>(payload.begin(), payload.end());
  port_->send(cpuPkt);
}

void MMU::setTid(uint64_t tid) { tid_ = tid; }

std::shared_ptr<Port<CPUMemoryPacket>> MMU::initDataPort() {
  port_ = std::make_shared<Port<CPUMemoryPacket>>();
  auto fn = [this](CPUMemoryPacket packet) -> void {
    pendingDataRequests_--;
    if (packet.type_ == MemoryAccessType::READ) {
      completedReads_.push_back(
          {{packet.vaddr_, packet.size_},
           RegisterValue(packet.payload_.data(), packet.size_),
           packet.id_});
    }
    // Currently, we ignore write responses.
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
  untimedInstrReadPort_->registerReceiver(fn);
  return untimedInstrReadPort_;
}

}  // namespace memory
}  // namespace simeng
