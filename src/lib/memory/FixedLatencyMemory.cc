#include "simeng/memory/FixedLatencyMemory.hh"

#include <algorithm>
#include <cstdint>
#include <memory>

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
  if (pkt->ignore()) {
    handleIgnoredRequest(pkt);
    port_->send(std::move(pkt));
    return;
  }
  if (pkt->isUntimedRead()) {
    pkt->turnIntoReadResponse(getUntimedData(pkt->paddr_, pkt->size_));
    port_->send(std::move(pkt));
    return;
  }
  LatencyPacket lpkt = {std::move(pkt), ticks_ + latency_};
  reqQueue_.push(std::move(lpkt));
}

void FixedLatencyMemory::handleReadRequest(std::unique_ptr<MemPacket>& req) {
  size_t size = req->size_;
  uint64_t addr = req->paddr_;
  req->turnIntoReadResponse(
      std::vector<char>(memory_.begin() + addr, memory_.begin() + addr + size));
}

void FixedLatencyMemory::handleWriteRequest(std::unique_ptr<MemPacket>& req) {
  uint64_t address = req->paddr_;
  std::copy(req->payload().begin(), req->payload().end(),
            memory_.begin() + address);
  req->turnIntoWriteResponse();
}

void FixedLatencyMemory::tick() {
  while (reqQueue_.front().endLat >= ticks_) {
    std::unique_ptr<MemPacket>& pkt = reqQueue_.front().req;
    if (pkt->isRequest() && pkt->isRead()) {
      handleReadRequest(pkt);
    } else if (pkt->isRequest() && pkt->isWrite()) {
      handleWriteRequest(pkt);
    } else {
      std::cerr << "[SimEng:SimpleMem] Invalid MemPacket type for "
                   "requesting access to memory. Requests to memory should "
                   "either be of "
                   "type READ_REQUEST or WRITE_REQUEST."
                << std::endl;
      pkt->setFault();
    }
    port_->send(std::move(pkt));
    reqQueue_.pop();
  }
  ticks_++;
};

void FixedLatencyMemory::sendUntimedData(std::vector<char> data, uint64_t addr,
                                         size_t size) {
  std::copy(data.begin(), data.begin() + size, memory_.begin() + addr);
}

std::vector<char> FixedLatencyMemory::getUntimedData(uint64_t paddr,
                                                     size_t size) {
  return std::vector<char>(memory_.begin() + paddr,
                           memory_.begin() + paddr + size);
}

void FixedLatencyMemory::handleIgnoredRequest(std::unique_ptr<MemPacket>& pkt) {
  if (pkt->isRead()) {
    pkt->turnIntoReadResponse(std::vector<char>(pkt->size_, '\0'));
  } else {
    pkt->turnIntoWriteResponse();
  }
}

std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
FixedLatencyMemory::initPort() {
  port_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    this->requestAccess(packet);
    return;
  };
  port_->registerReceiver(fn);
  return port_;
}

}  // namespace memory
}  // namespace simeng
