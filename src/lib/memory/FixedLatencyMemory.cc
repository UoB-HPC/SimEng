#include "simeng/memory/FixedLatencyMemory.hh"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

#include "simeng/memory/MemPacket.hh"

namespace simeng {
namespace memory {

FixedLatencyMemory::FixedLatencyMemory(size_t size, uint16_t latency) {
  memory_ = std::vector<char>(size, '\0');
  memSize_ = size;
  latency_ = latency;
}

size_t FixedLatencyMemory::getMemorySize() { return memSize_; }

void FixedLatencyMemory::requestAccess(std::unique_ptr<MemPacket>& pkt) {
  if (pkt->isUntimedRead()) {
    std::cerr << "Cannot do untimed memory access through timed port please use"
                 "the untimed port"
              << std::endl;
    pkt->setFault();
    timedPort_->send(std::move(pkt));
    return;
  }

  LatencyPacket lpkt = {std::move(pkt), ticks_ + latency_};
  reqQueue_.push(std::move(lpkt));
}

void FixedLatencyMemory::handleReadRequest(std::unique_ptr<MemPacket>& req) {
  req->cinfo.data = std::vector<char>(
      memory_.begin() + req->cinfo.basePaddr,
      memory_.begin() + req->cinfo.basePaddr + req->cinfo.size);
}

void FixedLatencyMemory::handleWriteRequest(std::unique_ptr<MemPacket>& req) {
  uint64_t address = req->cinfo.clineAddr;
  std::copy(req->cinfo.data.begin(), req->cinfo.data.end(),
            memory_.begin() + address);
}

void FixedLatencyMemory::tick() {
  ticks_++;
  while (reqQueue_.size() && ticks_ >= reqQueue_.front().endLat) {
    std::unique_ptr<MemPacket>& pkt = reqQueue_.front().req;
    if (pkt->cinfo.dirty) {
      handleWriteRequest(pkt);
    }
    handleReadRequest(pkt);
    timedPort_->send(std::move(pkt));
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

std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
FixedLatencyMemory::initPort() {
  timedPort_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    this->requestAccess(packet);
  };
  timedPort_->registerReceiver(fn);
  return timedPort_;
}

std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
FixedLatencyMemory::initUntimedPort() {
  untimedPort_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    if (!packet->isUntimedRead()) {
      std::cerr << "Cannot do timed access through untimed port please use the "
                   "timed port."
                << std::endl;
      std::exit(1);
    }
    packet->turnIntoReadResponse(getUntimedData(packet->paddr_, packet->size_));
    untimedPort_->send(std::move(packet));
  };
  untimedPort_->registerReceiver(fn);
  return untimedPort_;
}

}  // namespace memory
}  // namespace simeng
