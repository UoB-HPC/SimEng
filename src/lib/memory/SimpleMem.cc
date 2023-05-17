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
  if (pkt->isUntimedRead()) {
    std::cerr << "Cannot do untimed access through a timed port please used "
                 "the untimed port."
              << std::endl;
    pkt->setFault();
    return;
  }
  if (pkt->cinfo.dirty) {
    handleWriteRequest(pkt);
  }
  handleReadRequest(pkt);
}

void SimpleMem::handleReadRequest(std::unique_ptr<MemPacket>& req) {
  req->cinfo.data = std::vector<char>(
      memory_.begin() + req->cinfo.basePaddr,
      memory_.begin() + req->cinfo.basePaddr + req->cinfo.size);
}

void SimpleMem::handleWriteRequest(std::unique_ptr<MemPacket>& req) {
  uint64_t address = req->cinfo.clineAddr;
  std::copy(req->cinfo.data.begin(), req->cinfo.data.end(),
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

std::shared_ptr<Port<std::unique_ptr<MemPacket>>> SimpleMem::initPort() {
  timedPort_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    requestAccess(packet);
    timedPort_->send(std::move(packet));
  };
  timedPort_->registerReceiver(fn);
  return timedPort_;
}

std::shared_ptr<Port<std::unique_ptr<MemPacket>>> SimpleMem::initUntimedPort() {
  untimedPort_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();

  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    if (!packet->isUntimedRead()) {
      std::cerr << "Cannot do timed access through untimed port please use the "
                   "timed port."
                << std::endl;
      std::exit(1);
    }
    packet->turnIntoReadResponse(std::vector<char>(packet->size_, '\0'));
    untimedPort_->send(std::move(packet));
  };

  untimedPort_->registerReceiver(fn);
  return untimedPort_;
}

}  // namespace memory
}  // namespace simeng
