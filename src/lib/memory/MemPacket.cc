#include "simeng/memory/MemPacket.hh"

#include <memory>
#include <vector>

namespace simeng {
namespace memory {

MemPacket::MemPacket(uint64_t address, uint64_t size, MemPacketType type,
                     uint64_t reqId) {
  address_ = address;
  size_ = size;
  metadata_ = metadata_ | type;
  id_ = reqId;
}

std::unique_ptr<MemPacket> MemPacket::createReadRequest(uint64_t address,
                                                        uint64_t size,
                                                        uint64_t reqId) {
  return std::unique_ptr<MemPacket>(
      new MemPacket(address, size, READ_REQUEST, reqId));
}

std::unique_ptr<MemPacket> MemPacket::createWriteRequest(
    uint64_t address, uint64_t size, uint64_t reqId, std::vector<char> data) {
  return std::unique_ptr<MemPacket>(
      new DataPacket(address, size, WRITE_REQUEST, reqId, data));
}

std::unique_ptr<MemPacket> MemPacket::createReadResponse(
    uint64_t address, uint64_t size, uint64_t reqId, std::vector<char> data) {
  return std::unique_ptr<MemPacket>(
      new DataPacket(address, size, READ_RESPONSE, reqId, data));
}

std::unique_ptr<MemPacket> MemPacket::createWriteResponse(uint64_t address,
                                                          uint64_t size,
                                                          uint64_t reqId) {
  return std::unique_ptr<MemPacket>(
      new MemPacket(address, size, WRITE_RESPONSE, reqId));
}

std::unique_ptr<MemPacket> MemPacket::createFaultyMemPacket() {
  MemPacket* pkt = new MemPacket;
  pkt->metadata_ = FaultMask;
  return std::unique_ptr<MemPacket>(pkt);
}

std::unique_ptr<MemPacket> MemPacket::makeIntoReadResponse(
    std::vector<char> data) {
  return MemPacket::createReadResponse(address_, size_, id_, data);
}

std::unique_ptr<MemPacket> MemPacket::makeIntoWriteResponse() {
  return MemPacket::createWriteResponse(address_, size_, id_);
}

DataPacket::DataPacket(uint64_t address, uint64_t size, MemPacketType type,
                       uint64_t reqId, std::vector<char> data)
    : MemPacket(address, size, type, reqId) {
  metadata_ = metadata_ | PayloadMask;
  data_ = data;
}

}  // namespace memory
}  // namespace simeng
