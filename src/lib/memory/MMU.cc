#include "simeng/memory/MMU.hh"

#include "simeng/OS/Constants.hh"
namespace simeng {
namespace memory {

MMU::MMU(std::shared_ptr<Mem> memory, VAddrTranslator fn, uint64_t tid)
    : memory_(memory), translate_(fn), tid_(tid) {}

void MMU::bufferRequest(DataPacket request,
                        sendResponseToMemInterface sendResponse) {
  // Since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  uint64_t paddr = translate_(request.address_, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);
  DataPacket pkt;

  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    pkt = DataPacket(true);
  } else if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    pkt = memory_->handleIgnoredRequest(request);
  } else {
    request.address_ = paddr;
    pkt = memory_->requestAccess(request);
  }
  if (!(sendResponse == nullptr)) {
    sendResponse(pkt);
  }
}

void MMU::setTid(uint64_t tid) { tid_ = tid; }

}  // namespace memory
}  // namespace simeng
