#include "simeng/memory/MMU.hh"

#include "simeng/OS/Constants.hh"
namespace simeng {
namespace memory {

MMU::MMU(std::shared_ptr<Mem> memory, VAddrTranslator fn, uint64_t tid) {
  memory_ = memory;
  translate_ = fn;
  tid_ = tid;
};

void MMU::bufferRequest(
    DataPacket* request,
    std::function<void(DataPacket*)> sendRespToMemInterface) {
  // Since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  uint64_t paddr = translate_(request->address, tid_);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);

  if (faultCode == simeng::OS::masks::faults::pagetable::dataAbort) {
    sendRespToMemInterface(NULL);
  } else if (faultCode == simeng::OS::masks::faults::pagetable::ignored) {
    sendRespToMemInterface(memory_->handleIgnoredRequest(request));
  } else {
    request->address = paddr;
    DataPacket* response = memory_->requestAccess(request);
    sendRespToMemInterface(response);
  }
};

void MMU::setTid(uint64_t tid) { tid_ = tid; }

}  // namespace memory
}  // namespace simeng
