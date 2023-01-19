#include "simeng/memory/MMU.h"

namespace simeng {
namespace memory {

MMU::MMU(std::shared_ptr<Mem> memory, VAddrTranslator fn) {
  memory_ = memory;
  translate_ = fn;
};

void MMU::bufferRequest(DataPacket* request,
                        std::function<void(DataPacket*)> callback) {
  // since we don't have a TLB yet, treat every memory request as a TLB miss and
  // consult the page table.
  uint64_t paddr = translate_(request->address);
  request->address = paddr;
  DataPacket* response = memory_->requestAccess(request);
  callback(response);
};

void MMU::setTranslator(VAddrTranslator translator) { translate_ = translator; }

}  // namespace memory
}  // namespace simeng
