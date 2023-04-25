#include "simeng/memory/SimpleMem.hh"

#include <algorithm>
#include <memory>

#include "simeng/memory/MemPacket.hh"

namespace simeng {
namespace memory {

SimpleMem::SimpleMem(size_t size) {
  memory_ = std::vector<char>(size, '\0');
  memSize_ = size;
}

size_t SimpleMem::getMemorySize() { return memSize_; }

void SimpleMem::requestAccess(std::unique_ptr<MemPacket>& pkt) {
  if (pkt->ignore()) {
    handleIgnoredRequest(pkt);
  } else if (pkt->isRequest() && pkt->isRead()) {
    handleReadRequest(pkt);
  } else if (pkt->isRequest() && pkt->isWrite()) {
    handleWriteRequest(pkt);
  } else {
    std::cerr << "[SimEng:SimpleMem] Invalid MemPacket type for "
                 "requesting access to memory. Requests to memory should "
                 "either be of "
                 "type READ_REQUEST or WRITE_REQUEST."
              << std::endl;
    pkt->markAsFaulty();
  }
  port_->send(std::move(pkt));
}

void SimpleMem::handleReadRequest(std::unique_ptr<MemPacket>& req) {
  size_t size = req->size_;
  uint64_t addr = req->paddr_;
  req->turnIntoReadResponse(
      std::vector<char>(memory_.begin() + addr, memory_.begin() + addr + size));
}

void SimpleMem::handleWriteRequest(std::unique_ptr<MemPacket>& req) {
  uint64_t address = req->paddr_;
  std::copy(req->payload().begin(), req->payload().end(),
            memory_.begin() + address);
  req->turnIntoWriteResponse();
}

void SimpleMem::sendUntimedData(std::vector<char> data, uint64_t addr,
                                size_t size) {
  std::copy(data.begin(), data.begin() + size, memory_.begin() + addr);
}

std::vector<char> SimpleMem::getUntimedData(uint64_t paddr, size_t size) {
  return std::vector<char>(memory_.begin() + paddr,
                           memory_.begin() + paddr + size);
}

void SimpleMem::handleIgnoredRequest(std::unique_ptr<MemPacket>& pkt) {
  if (pkt->isRead()) {
    pkt->turnIntoReadResponse(std::vector<char>(pkt->size_, '\0'));
  } else {
    pkt->turnIntoWriteResponse();
  }
}

std::shared_ptr<Port<std::unique_ptr<MemPacket>>> SimpleMem::initPort() {
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
