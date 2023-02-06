#include "simeng/memory/MMU.hh"

#include "simeng/kernel/Masks.hh"
namespace simeng {
namespace memory {

MMU::MMU(std::shared_ptr<Mem> memory, VAddrTranslator fn, uint64_t pid) {
  memory_ = memory;
  translate_ = fn;
  pid_ = pid;
};

void MMU::bufferRequest(DataPacket* request,
                        std::function<void(DataPacket*)> callback) {
  // since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  uint64_t paddr = translate_(request->address, pid_);
  uint64_t faultCode = simeng::kernel::masks::faults::getFaultCode(paddr);

  if (faultCode == simeng::kernel::masks::faults::pagetable::dataAbort) {
    callback(NULL);
  } else if (faultCode == simeng::kernel::masks::faults::pagetable::ignored) {
    callback(memory_->handleIgnoredRequest(request));
  } else {
    request->address = paddr;
    DataPacket* response = memory_->requestAccess(request);
    callback(response);
  }
};

void MMU::setPid(uint64_t pid) { pid_ = pid; }

}  // namespace memory
}  // namespace simeng
