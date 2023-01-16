#include "simeng/memory/SimpleMem.hh"

namespace simeng {
namespace memory {

SimpleMem::SimpleMem(size_t size) {
  memRef = new char[size];
  std::memset(memRef, 0, size);
  memory_ = span<char>(memRef, size);
  memSize_ = size;
}

SimpleMem::~SimpleMem() { delete[] memRef; };

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

char* SimpleMem::getMemCpy() {
  char* ret = new char[memSize_];
  std::copy(memory_.begin(), memory_.end(), ret);
  return ret;
}

}  // namespace memory
}  // namespace simeng