#include "simeng/memory/MMU.hh"

#include "simeng/OS/Constants.hh"
namespace simeng {
namespace memory {

MMU::MMU(std::shared_ptr<Mem> memory, uint16_t latency, VAddrTranslator fn,
         uint64_t tid)
    : memory_(memory), latency_(latency), tid_(tid), translate_(fn) {}

void MMU::tick() {
  tickCounter_++;

  while (pendingRequests_.size() > 0) {
    const auto& request = pendingRequests_.front();

    if (request.readyAt > tickCounter_) {
      // Head of queue isn't ready yet; end cycle
      break;
    }

    const auto& target = request.target;
    uint64_t requestId = request.requestId;

    if (request.write) {
      const char* wdata = request.data.getAsVector<char>();
      std::vector<char> dt(wdata, wdata + target.size);
      // Responses to write requests are ignored by passing in a nullptr
      // callback because they don't contain any information relevant to the
      // simulation.
      bufferRequest(memory::DataPacket(target.address, target.size,
                                       memory::WRITE_REQUEST, requestId, dt),
                    nullptr);
    } else {
      // Instantiate a callback function which will be invoked with the response
      // to a read request.
      auto fn = [this, target,
                 requestId](struct memory::DataPacket packet) -> void {
        if (packet.inFault_) {
          completedReads_.push_back({target, RegisterValue(), requestId});
          return;
        }
        completedReads_.push_back(
            {target, RegisterValue(packet.data_.data(), packet.size_),
             requestId});
      };
      bufferRequest(memory::DataPacket(target.address, target.size,
                                       memory::READ_REQUEST, requestId),
                    fn);
    }

    // Remove the request from the queue
    pendingRequests_.pop();
  }
}

void MMU::requestRead(const MemoryAccessTarget& target, uint64_t requestId) {
  pendingRequests_.push({target, tickCounter_ + latency_, requestId});
}

void MMU::requestWrite(const MemoryAccessTarget& target,
                       const RegisterValue& data) {
  pendingRequests_.push({target, data, tickCounter_ + latency_});
}

void MMU::requestInstrRead(const MemoryAccessTarget& target,
                           uint64_t requestId) {
  // Instantiate a callback function which will be invoked with the response
  // to a read request.
  auto fn = [this, target, requestId](memory::DataPacket dpkt) -> void {
    if (dpkt.inFault_) {
      completedInstrReads_.push_back({target, RegisterValue(), requestId});
      return;
    }
    completedInstrReads_.push_back(
        {target, RegisterValue(dpkt.data_.data(), dpkt.size_), requestId});
  };

  bufferRequest(memory::DataPacket(target.address, target.size,
                                   memory::READ_REQUEST, requestId),
                fn);
}

const span<MemoryReadResult> MMU::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

const span<MemoryReadResult> MMU::getCompletedInstrReads() const {
  return {const_cast<MemoryReadResult*>(completedInstrReads_.data()),
          completedInstrReads_.size()};
}

void MMU::clearCompletedReads() { completedReads_.clear(); }

void MMU::clearCompletedIntrReads() { completedInstrReads_.clear(); }

bool MMU::hasPendingRequests() const { return !pendingRequests_.empty(); }

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
