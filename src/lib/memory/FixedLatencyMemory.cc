#include "simeng/memory/FixedLatencyMemory.hh"

#include <algorithm>
#include <cstdint>
#include <memory>

namespace simeng {
namespace memory {

FixedLatencyMemory::FixedLatencyMemory(size_t size, uint16_t latency) {
  memory_ = std::vector<char>(size, '\0');
  memSize_ = size;
  latency_ = latency;
}

size_t FixedLatencyMemory::getMemorySize() { return memSize_; }

void FixedLatencyMemory::requestAccess(std::unique_ptr<MemPacket> pkt) {
  if (pkt->ignore()) {
    port_->send(handleIgnoredRequest(std::move(pkt)));
  }
  LatencyPacket lpkt = {std::move(pkt), ticks_ + latency_};
  reqQueue_.push(std::move(lpkt));
}

void FixedLatencyMemory::tick() {
  while (reqQueue_.front().endLat >= ticks_) {
    auto req = std::move(reqQueue_.front().req);
    if (req->isRequest() && req->isRead()) {
      port_->send(handleReadRequest(std::move(req)));
    } else if (req->isRequest() && req->isWrite()) {
      port_->send(handleWriteRequest(std::move(req)));
    } else {
      std::cerr << "[SimEng:FixedLatencyMemory] Invalid MemPacket type for "
                   "requesting access to memory. Requests to memory should "
                   "either be of "
                   "type READ_REQUEST or WRITE_REQUEST."
                << std::endl;
      port_->send(MemPacket::createFaultyMemPacket());
    }
    reqQueue_.pop();
  }
  ticks_++;
};

std::unique_ptr<MemPacket> FixedLatencyMemory::handleReadRequest(
    std::unique_ptr<MemPacket> req) {
  size_t size = req->size_;
  uint64_t addr = req->paddr_;
  std::vector<char> data(memory_.begin() + addr, memory_.begin() + addr + size);
  req->turnIntoReadResponse(data);
  return req;
}

std::unique_ptr<MemPacket> FixedLatencyMemory::handleWriteRequest(
    std::unique_ptr<MemPacket> req) {
  uint64_t address = req->paddr_;
  std::copy(req->data().begin(), req->data().end(), memory_.begin() + address);
  req->turnIntoWriteResponse();
  return req;
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

std::unique_ptr<MemPacket> FixedLatencyMemory::handleIgnoredRequest(
    std::unique_ptr<MemPacket> pkt) {
  if (pkt->isRead()) {
    pkt->turnIntoReadResponse(std::vector<char>(pkt->size_, '\0'));
  } else {
    pkt->turnIntoWriteResponse();
  }
  return pkt;
}

Port<std::unique_ptr<MemPacket>>* FixedLatencyMemory::initPort() {
  port_ = new Port<std::unique_ptr<MemPacket>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    this->requestAccess(std::move(packet));
    return;
  };
  port_->registerReceiver(fn);
  return port_;
}

}  // namespace memory
}  // namespace simeng