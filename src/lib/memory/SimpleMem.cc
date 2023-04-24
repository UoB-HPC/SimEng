#include "simeng/memory/SimpleMem.hh"

#include <algorithm>
#include <memory>

namespace simeng {
namespace memory {

SimpleMem::SimpleMem(size_t size) {
  memory_ = std::vector<char>(size, '\0');
  memSize_ = size;
}

size_t SimpleMem::getMemorySize() { return memSize_; }

void SimpleMem::requestAccess(std::unique_ptr<MemPacket> pkt) {
  if (pkt->ignore()) {
    port_->send(handleIgnoredRequest(std::move(pkt)));
  } else if (pkt->isUntimedRead()) {
    std::vector<char> data = getUntimedData(pkt->paddr_, pkt->size_);
    pkt->turnIntoReadResponse(data);
    port_->send(std::move(pkt));
  } else if (pkt->isRequest() && pkt->isRead()) {
    port_->send(handleReadRequest(std::move(pkt)));
  } else if (pkt->isRequest() && pkt->isWrite()) {
    port_->send(handleWriteRequest(std::move(pkt)));
  } else {
    std::cerr << "[SimEng:SimpleMem] Invalid MemPacket type for "
                 "requesting access to memory. Requests to memory should "
                 "either be of "
                 "type READ_REQUEST or WRITE_REQUEST."
              << std::endl;
    port_->send(MemPacket::createFaultyMemPacket(pkt->isRead()));
  }
}

std::unique_ptr<MemPacket> SimpleMem::handleReadRequest(
    std::unique_ptr<MemPacket> req) {
  size_t size = req->size_;
  uint64_t addr = req->paddr_;
  std::vector<char> data(memory_.begin() + addr, memory_.begin() + addr + size);
  req->turnIntoReadResponse(data);
  return req;
}

std::unique_ptr<MemPacket> SimpleMem::handleWriteRequest(
    std::unique_ptr<MemPacket> req) {
  uint64_t address = req->paddr_;
  std::copy(req->data().begin(), req->data().end(), memory_.begin() + address);
  req->turnIntoWriteResponse();
  return req;
}

void SimpleMem::sendUntimedData(std::vector<char> data, uint64_t addr,
                                size_t size) {
  std::copy(data.begin(), data.begin() + size, memory_.begin() + addr);
}

std::vector<char> SimpleMem::getUntimedData(uint64_t paddr, size_t size) {
  return std::vector<char>(memory_.begin() + paddr,
                           memory_.begin() + paddr + size);
}

std::unique_ptr<MemPacket> SimpleMem::handleIgnoredRequest(
    std::unique_ptr<MemPacket> pkt) {
  if (pkt->isRead()) {
    pkt->turnIntoReadResponse(std::vector<char>(pkt->size_, '\0'));
  } else {
    pkt->turnIntoWriteResponse();
  }
  return pkt;
}

Port<std::unique_ptr<MemPacket>>* SimpleMem::initPort() {
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
