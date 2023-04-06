#include "simeng/memory/MMU.hh"

#include <memory>

#include "simeng/OS/Constants.hh"
namespace simeng {
namespace memory {

MMU::MMU(VAddrTranslator fn, uint64_t tid) : translate_(fn), tid_(tid) {}

void MMU::bufferRequest(std::unique_ptr<MemPacket> request,
                        sendResponseToMemInterface sendResponse) {
  // Since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  sendResponse_ = sendResponse;
  uint64_t paddr = translate_(request->address_, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);

  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    this->sendResponse_(MemPacket::createFaultyMemPacket());
    return;
  } else if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    request->setIgnored();
  } else {
    request->address_ = paddr;
  }
  port_->send(std::move(request));
}

void MMU::setTid(uint64_t tid) { tid_ = tid; }

Port<std::unique_ptr<MemPacket>>* MMU::initPort() {
  port_ = new Port<std::unique_ptr<MemPacket>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    if (this->sendResponse_ != nullptr) {
      this->sendResponse_(std::move(packet));
    }
    return;
  };
  port_->registerReceiver(fn);
  return port_;
}

}  // namespace memory
}  // namespace simeng
