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

void FixedLatencyMemory::sendUntimedData(std::vector<char> data, uint64_t addr,
                                         size_t size) {
  std::copy(data.begin(), data.begin() + size, memory_.begin() + addr);
}

std::vector<char> FixedLatencyMemory::getUntimedData(uint64_t paddr,
                                                     size_t size) {
  return std::vector<char>(memory_.begin() + paddr,
                           memory_.begin() + paddr + size);
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

std::shared_ptr<FixedLatencyMemory> FixedLatencyMemory::build(
    bool hasHierarchy, size_t bytes, uint16_t latency) {
  if (hasHierarchy) {
    return std::shared_ptr<
        DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>>(
        new DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>(
            bytes, latency));
  }
  return std::shared_ptr<
      DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>>(
      new DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>(
          bytes, latency));
};

DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>::
    DerivedFixedLatencyMemory(size_t bytes, uint16_t latency)
    : FixedLatencyMemory(bytes, latency) {}

void DerivedFixedLatencyMemory<
    FixedLatencyMemoryType::NoHierarchy>::requestAccess(CPUMemoryPacket& pkt) {
  LatencyPacket<CPUMemoryPacket> lpkt = {pkt, ticks_ + latency_};
  cpuReqQueue_.push(lpkt);
}

void DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>::tick() {
  ticks_++;

  while (cpuReqQueue_.size() && ticks_ >= cpuReqQueue_.front().endLat) {
    CPUMemoryPacket& pkt = cpuReqQueue_.front().req;
    if (pkt.type_ == MemoryAccessType::WRITE) {
      handleWriteRequest(pkt);
    } else {
      handleReadRequest(pkt);
    }
    directAccessDataPort_->send(pkt);
    cpuReqQueue_.pop();
  }
}

void DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>::
    handleReadRequest(CPUMemoryPacket& req) {
  req.payload_ = std::vector<char>(memory_.begin() + req.paddr_,
                                   memory_.begin() + req.paddr_ + req.size_);
}

void DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>::
    handleWriteRequest(CPUMemoryPacket& req) {
  uint64_t address = req.paddr_;
  std::copy(req.payload_.begin(), req.payload_.end(),
            memory_.begin() + address);
}

std::shared_ptr<Port<CPUMemoryPacket>> DerivedFixedLatencyMemory<
    FixedLatencyMemoryType::NoHierarchy>::initDirectAccessDataPort() {
  directAccessDataPort_ = std::make_shared<Port<CPUMemoryPacket>>();
  auto fn = [this](CPUMemoryPacket packet) -> void {
    this->requestAccess(packet);
  };
  directAccessDataPort_->registerReceiver(fn);
  return directAccessDataPort_;
}

std::shared_ptr<Port<MemoryHierarchyPacket>>
DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>::initDataPort() {
  std::exit(1);
}

DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>::
    DerivedFixedLatencyMemory(size_t bytes, uint16_t latency)
    : FixedLatencyMemory(bytes, latency) {}

void DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>::
    requestAccess(MemoryHierarchyPacket& pkt) {
  LatencyPacket<MemoryHierarchyPacket> lpkt = {pkt, ticks_ + latency_};
  reqQueue_.push(lpkt);
}

void DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>::
    handleWriteRequest(MemoryHierarchyPacket& req) {
  uint64_t address = req.clineAddr_;
  std::copy(req.payload_.begin(), req.payload_.end(),
            memory_.begin() + address);
}

void DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>::
    handleReadRequest(MemoryHierarchyPacket& req) {
  uint64_t downAlignedAddr = downAlign(req.paddr_, MemoryHierarchyPacket::clw);
  req.payload_ =
      std::vector<char>(memory_.begin() + downAlignedAddr,
                        memory_.begin() + downAlignedAddr + req.size_);
}

void DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>::tick() {
  ticks_++;

  while (reqQueue_.size() && ticks_ >= reqQueue_.front().endLat) {
    MemoryHierarchyPacket& pkt = reqQueue_.front().req;
    if (pkt.isDirty) {
      handleWriteRequest(pkt);
    }
    handleReadRequest(pkt);
    timedPort_->send(pkt);
    reqQueue_.pop();
  }
}

std::shared_ptr<Port<MemoryHierarchyPacket>> DerivedFixedLatencyMemory<
    FixedLatencyMemoryType::WithHierarchy>::initDataPort() {
  timedPort_ = std::make_shared<Port<MemoryHierarchyPacket>>();
  auto fn = [this](MemoryHierarchyPacket packet) -> void {
    this->requestAccess(packet);
  };
  timedPort_->registerReceiver(fn);
  return timedPort_;
}

std::shared_ptr<Port<CPUMemoryPacket>> DerivedFixedLatencyMemory<
    FixedLatencyMemoryType::WithHierarchy>::initDirectAccessDataPort() {
  std::exit(1);
}

}  // namespace memory
}  // namespace simeng
