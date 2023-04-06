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

std::unique_ptr<MemPacket> SimpleMem::requestAccess(
    std::unique_ptr<MemPacket> pkt) {
  if (pkt->ignore()) {
    return handleIgnoredRequest(std::move(pkt));
  }
  if (pkt->isRequest() && pkt->isRead()) {
    return handleReadRequest(std::move(pkt));
  }
  if (pkt->isRequest() && pkt->isWrite()) {
    return handleWriteRequest(std::move(pkt));
  }
  std::cerr
      << "[SimEng:SimpleMem] Invalid MemPacket type for "
         "requesting access to memory. Requests to memory should either be of "
         "type READ_REQUEST or WRITE_REQUEST."
      << std::endl;
  return MemPacket::createFaultyMemPacket();
}

std::unique_ptr<MemPacket> SimpleMem::handleReadRequest(
    std::unique_ptr<MemPacket> req) {
  size_t size = req->size_;
  uint64_t addr = req->address_;
  std::vector<char> data(memory_.begin() + addr, memory_.begin() + addr + size);
  return MemPacket::createReadResponse(addr, size, req->id_, data);
}

std::unique_ptr<MemPacket> SimpleMem::handleWriteRequest(
    std::unique_ptr<MemPacket> req) {
  uint64_t address = req->address_;
  std::copy(req->data().begin(), req->data().end(), memory_.begin() + address);
  return MemPacket::createWriteResponse(address, req->size_, req->id_);
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
  if (pkt->isRead() && pkt->isRequest()) {
    return MemPacket::createReadResponse(pkt->address_, pkt->size_, pkt->id_,
                                         std::vector<char>(pkt->size_, '\0'));
  }
  return MemPacket::createWriteResponse(pkt->address_, pkt->size_, pkt->id_);
}

Port<std::unique_ptr<MemPacket>>* SimpleMem::initPort() {
  port_ = new Port<std::unique_ptr<MemPacket>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    auto pkt = this->requestAccess(std::move(packet));
    port_->send(std::move(pkt));
    return;
  };
  port_->registerReceiver(fn);
  return port_;
}

}  // namespace memory
}  // namespace simeng
