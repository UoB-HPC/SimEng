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
    return update(
        std::unique_ptr<MemPacket>(MemPacket::createFaultyMemPacket()));
  } else if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    request->setIgnored();
  } else {
    request->address_ = paddr;
  }
  return notify(std::move(request));
}

void MMU::subscribe(
    std::shared_ptr<SubscriberInterface<std::unique_ptr<MemPacket>>> sub) {
  subscriber_ = sub;
}
void MMU::notify(std::unique_ptr<MemPacket> data) {
  subscriber_->update(std::move(data));
}
void MMU::update(std::unique_ptr<MemPacket> packet) {
  if (!(sendResponse_ == nullptr)) sendResponse_(std::move(packet));
}

void MMU::setTid(uint64_t tid) { tid_ = tid; }

}  // namespace memory
}  // namespace simeng
