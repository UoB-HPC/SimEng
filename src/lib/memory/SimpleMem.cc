#include "simeng/memory/SimpleMem.hh"

#include <algorithm>
#include <cstdint>
#include <memory>

#include "simeng/memory/MemPacket.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace memory {

SimpleMem::SimpleMem(size_t size) {
  memory_ = std::vector<char>(size, '\0');
  memSize_ = size;
}

size_t SimpleMem::getMemorySize() { return memSize_; }

void SimpleMem::requestAccess(MemoryHierarchyPacket& pkt) {
  if (pkt.type_ == MemoryAccessType::WRITE) {
    handleWriteRequest(pkt);
  }
  handleReadRequest(pkt);
}

void SimpleMem::handleReadRequest(MemoryHierarchyPacket& req) {
  uint64_t downAlignedAddr = downAlign(req.paddr_, MemoryHierarchyPacket::clw);
  req.payload_ =
      std::vector<char>(memory_.begin() + downAlignedAddr,
                        memory_.begin() + downAlignedAddr + req.size_);
}

void SimpleMem::handleWriteRequest(MemoryHierarchyPacket& req) {
  uint64_t address = req.clineAddr_;
  std::copy(req.payload_.begin(), req.payload_.end(),
            memory_.begin() + address);
}

void SimpleMem::sendUntimedData(std::vector<char> data, uint64_t addr,
                                size_t size) {
  std::copy(data.begin(), data.begin() + size, memory_.begin() + addr);
}

std::vector<char> SimpleMem::getUntimedData(uint64_t paddr, size_t size) {
  return std::vector<char>(memory_.begin() + paddr,
                           memory_.begin() + paddr + size);
}

std::shared_ptr<Port<MemoryHierarchyPacket>> SimpleMem::initPort() {
  timedPort_ = std::make_shared<Port<MemoryHierarchyPacket>>();
  auto fn = [this](MemoryHierarchyPacket packet) -> void {
    requestAccess(packet);
    timedPort_->send(packet);
  };
  timedPort_->registerReceiver(fn);
  return timedPort_;
}

std::shared_ptr<Port<CPUMemoryPacket>> SimpleMem::initUntimedInstrReadPort() {
  untimedInstrReadPort_ = std::make_shared<Port<CPUMemoryPacket>>();

  auto fn = [this](CPUMemoryPacket packet) -> void {
    if (packet.type_ == MemoryAccessType::WRITE) {
      std::cerr << "[SimEng::SimpleMem] Cannot perform a write operation "
                   "through the untimed instruction read port please use the "
                   "timed port."
                << std::endl;
      std::exit(1);
    }
    packet.payload_ = getUntimedData(packet.paddr_, packet.size_);
    untimedInstrReadPort_->send(packet);
  };

  untimedInstrReadPort_->registerReceiver(fn);
  return untimedInstrReadPort_;
}

}  // namespace memory
}  // namespace simeng
