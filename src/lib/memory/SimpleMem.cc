#include "simeng/memory/SimpleMem.hh"

namespace simeng {
namespace memory {

SimpleMem::SimpleMem(size_t size) {
  memRef_ = new char[size];
  std::memset(memRef_, 0, size);
  memory_ = span<char>(memRef_, size);

  faultMemory_ = new char[128];
  std::memset(faultMemory_, 0, 128);
  memSize_ = size;
}

SimpleMem::~SimpleMem() {
  delete[] memRef_;
  delete[] faultMemory_;
};

size_t SimpleMem::getMemorySize() { return memSize_; }

DataPacket* SimpleMem::requestAccess(struct DataPacket* pkt) {
  if (pkt->type == READ) {
    struct ReadPacket* rreq = (ReadPacket*)pkt;
    auto resp = handleReadRequest(rreq);
    delete rreq;
    return resp;
  };
  struct WritePacket* wreq = (WritePacket*)pkt;
  auto resp = handleWriteRequest(wreq);
  delete wreq;
  return resp;
};

ReadRespPacket* SimpleMem::handleReadRequest(struct ReadPacket* req) {
  size_t size = req->size;
  uint64_t addr = req->address;
  char* data = new char[size];
  char* startAddr = memory_.begin() + addr;
  std::copy(startAddr, startAddr + size, data);
  return req->makeResponse(size, data);
};

WriteRespPacket* SimpleMem::handleWriteRequest(struct WritePacket* req) {
  uint64_t address = req->address;
  size_t size = req->size;
  const char* data = req->data;
  std::copy(data, data + size, memory_.begin() + address);
  return req->makeResponse(size);
};

void SimpleMem::sendUntimedData(char* data, uint64_t addr, size_t size) {
  std::copy(data, data + size, memory_.begin() + addr);
  return;
}

char* SimpleMem::getUntimedData(uint64_t paddr, size_t size) {
  char* ret = new char[size];
  std::copy(memory_.begin() + paddr, memory_.begin() + paddr + size, ret);
  return ret;
}

DataPacket* SimpleMem::handleIgnoredRequest(DataPacket* pkt) {
  if (pkt->type == READ) {
    struct ReadPacket* rreq = (ReadPacket*)pkt;
    auto resp = rreq->makeResponse(rreq->size, faultMemory_);
    delete rreq;
    return resp;
  }
  struct WritePacket* wreq = (WritePacket*)pkt;
  auto resp = wreq->makeResponse(wreq->size);
  delete wreq;
  return resp;
}

}  // namespace memory
}  // namespace simeng
