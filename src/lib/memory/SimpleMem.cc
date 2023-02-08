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

ReadResponse SimpleMem::readData(ReadRequest req) {
  ReadResponse::data_type arr;
  size_t size = req.size_;
  uint64_t addr = req.address_;
  char* startAddr = memory_.begin() + addr;
  std::copy(startAddr, startAddr + size, arr.begin());
  return ReadResponse{req.address_, req.size_, arr};
};

WriteResponse SimpleMem::writeData(WriteRequest req) {
  uint64_t address = req.address_;
  WriteRequest::data_type data = req.data();
  std::copy(data.begin(), data.end(), memory_.begin() + address);
  return WriteResponse{req.address_, req.size_};
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

ReadResponse SimpleMem::handleIgnoredRequest(ReadRequest req) {
  ReadResponse::data_type arr;
  std::copy(faultMemory_, faultMemory_ + 16, arr.begin());
  return ReadResponse{req.address_, 0, arr};
}

WriteResponse SimpleMem::handleIgnoredRequest(WriteRequest req) {
  return WriteResponse{req.address_, 0};
}

}  // namespace memory
}  // namespace simeng
