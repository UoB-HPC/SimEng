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
  pkt->printMetadata();
  std::cout << pkt->isRequest() << std::endl;
  std::cout << pkt->isFaulty() << std::endl;
  std::cout << pkt->hasPayload() << std::endl;
  std::cerr
      << "[SimEng:SimpleMem] Invalid MemPacket type for "
         "requesting access to memory. Requests to memory should either be of "
         "type READ_REQUEST or WRITE_REQUEST."
      << std::endl;
  return std::unique_ptr<MemPacket>(MemPacket::createFaultyMemPacket());
}

std::unique_ptr<MemPacket> SimpleMem::handleReadRequest(
    std::unique_ptr<MemPacket> req) {
  size_t size = req->size_;
  uint64_t addr = req->address_;
  std::vector<char> data(memory_.begin() + addr, memory_.begin() + addr + size);
  return std::unique_ptr<MemPacket>(req->makeIntoReadResponse(data));
}

std::unique_ptr<MemPacket> SimpleMem::handleWriteRequest(
    std::unique_ptr<MemPacket> req) {
  uint64_t address = req->address_;
  std::copy(req->data().begin(), req->data().end(), memory_.begin() + address);
  return std::unique_ptr<MemPacket>(req->makeIntoWriteResponse());
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
    return std::unique_ptr<MemPacket>(
        pkt->makeIntoReadResponse(std::vector<char>(pkt->size_, '\0')));
  }
  return std::unique_ptr<MemPacket>(pkt->makeIntoWriteResponse());
}

void SimpleMem::subscribe(
    std::shared_ptr<SubscriberInterface<std::unique_ptr<MemPacket>>> sub) {
  subscriber_ = sub;
};

void SimpleMem::notify(std::unique_ptr<MemPacket> data) {
  subscriber_->update(std::move(data));
}

void SimpleMem::update(std::unique_ptr<MemPacket> packet) {
  auto res = requestAccess(std::move(packet));
  notify(std::move(res));
}

}  // namespace memory
}  // namespace simeng
