#include "simeng/memory/SimpleMem.hh"

#include <algorithm>

namespace simeng {
namespace memory {

SimpleMem::SimpleMem(size_t size) {
  memory_ = std::vector<char>(size, '\0');
  memSize_ = size;
}

size_t SimpleMem::getMemorySize() { return memSize_; }

DataPacket SimpleMem::requestAccess(struct DataPacket pkt) {
  if (pkt.type_ == READ_REQUEST) {
    return handleReadRequest(pkt);
  } else if (pkt.type_ == WRITE_REQUEST) {
    return handleWriteRequest(pkt);
  } else {
    std::cerr << "[SimEng:SimpleMem] Invalid DataPacket type for requesting "
                 "access to memory. Requests to memory should either be of "
                 "type READ_REQUEST or WRITE_REQUEST."
              << std::endl;
    return DataPacket(true);
  }
}

DataPacket SimpleMem::handleReadRequest(struct DataPacket req) {
  size_t size = req.size_;
  uint64_t addr = req.address_;
  std::vector<char> data(memory_.begin() + addr, memory_.begin() + addr + size);
  return req.makeIntoReadResponse(data);
}

DataPacket SimpleMem::handleWriteRequest(struct DataPacket req) {
  uint64_t address = req.address_;
  std::copy(req.data_.begin(), req.data_.end(), memory_.begin() + address);
  return req.makeIntoWriteResponse();
}

void SimpleMem::sendUntimedData(std::vector<char> data, uint64_t addr,
                                size_t size) {
  std::copy(data.begin(), data.begin() + size, memory_.begin() + addr);
}

std::vector<char> SimpleMem::getUntimedData(uint64_t paddr, size_t size) {
  return std::vector<char>(memory_.begin() + paddr,
                           memory_.begin() + paddr + size);
}

DataPacket SimpleMem::handleIgnoredRequest(struct DataPacket pkt) {
  if (pkt.type_ == READ_REQUEST) {
    return pkt.makeIntoReadResponse(std::vector<char>(pkt.size_, '\0'));
  }
  return pkt.makeIntoWriteResponse();
}

}  // namespace memory
}  // namespace simeng
