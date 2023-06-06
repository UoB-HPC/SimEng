#include "simeng/memory/FixedLatencyMemory.hh"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

#include "simeng/Config.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace memory {

FixedLatencyMemory::FixedLatencyMemory(size_t size, uint16_t latency) {
  memory_ = std::vector<char>(size, '\0');
  memSize_ = size;
  latency_ = latency;
}

size_t FixedLatencyMemory::getMemorySize() { return memSize_; }

void FixedLatencyMemory::requestAccess(MemoryHierarchyPacket& pkt) {
  LatencyPacket lpkt = {pkt, ticks_ + latency_};
  reqQueue_.push(lpkt);
}

void FixedLatencyMemory::handleReadRequest(MemoryHierarchyPacket& req) {
  uint64_t downAlignedAddr = downAlign(req.paddr_, MemoryHierarchyPacket::clw);
  req.payload_ =
      std::vector<char>(memory_.begin() + downAlignedAddr,
                        memory_.begin() + downAlignedAddr + req.size_);
}

void FixedLatencyMemory::handleWriteRequest(MemoryHierarchyPacket& req) {
  uint64_t address = req.clineAddr_;
  std::copy(req.payload_.begin(), req.payload_.end(),
            memory_.begin() + address);
}

void FixedLatencyMemory::tick() {
  ticks_++;
  while (reqQueue_.size() && ticks_ >= reqQueue_.front().endLat) {
    MemoryHierarchyPacket& pkt = reqQueue_.front().req;
    if (pkt.type_ == MemoryAccessType::WRITE) {
      handleWriteRequest(pkt);
    }
    handleReadRequest(pkt);
    timedPort_->send(pkt);
    reqQueue_.pop();
  }
}

void FixedLatencyMemory::sendUntimedData(std::vector<char> data, uint64_t addr,
                                         size_t size) {
  std::copy(data.begin(), data.begin() + size, memory_.begin() + addr);
}

std::vector<char> FixedLatencyMemory::getUntimedData(uint64_t paddr,
                                                     size_t size) {
  return std::vector<char>(memory_.begin() + paddr,
                           memory_.begin() + paddr + size);
}

std::shared_ptr<Port<MemoryHierarchyPacket>> FixedLatencyMemory::initPort() {
  timedPort_ = std::make_shared<Port<MemoryHierarchyPacket>>();
  auto fn = [this](MemoryHierarchyPacket packet) -> void {
    this->requestAccess(packet);
  };
  timedPort_->registerReceiver(fn);
  return timedPort_;
}

std::shared_ptr<Port<CPUMemoryPacket>>
FixedLatencyMemory::initUntimedInstrReadPort() {
  untimedInstrReadPort_ = std::make_shared<Port<CPUMemoryPacket>>();
  auto fn = [this](CPUMemoryPacket packet) -> void {
    if (packet.type_ == MemoryAccessType::WRITE) {
      std::cerr << "[SimEng:FixedLatencyMemory] Cannot perform a write "
                   "operation through the untimed instruction read port "
                   "please use the "
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
