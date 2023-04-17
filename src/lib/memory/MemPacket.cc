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

MemPacket::MemPacket(uint64_t address, uint64_t size, MemPacketType type,
                     uint64_t reqId, std::vector<char> data) {
  address_ = address;
  size_ = size;
  metadata_ = metadata_ | type;
  id_ = reqId;
  data_ = data;
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
      new MemPacket(address, size, WRITE_REQUEST, reqId, data));
}

void MemPacket::turnIntoWriteResponse() {
  if (!isRequest() & !isWrite()) {
    std::cerr << "[SimEng:MemPacket] Only MemPackets of type Write Request can "
                 "be changed into Write Response"
              << std::endl;
    std::exit(1);
  }
  metadata_ = metadata_ & 0b01111111;
}

void MemPacket::turnIntoReadResponse(std::vector<char> data) {
  if (!isRequest() & !isRead()) {
    std::cerr << "[SimEng:MemPacket] Only MemPackets of type Read Request can "
                 "be changed into Read Response"
              << std::endl;
    std::exit(1);
  }
  metadata_ = metadata_ & 0b00111111;
  data_ = data;
}

std::unique_ptr<MemPacket> MemPacket::createFaultyMemPacket() {
  MemPacket* pkt = new MemPacket;
  pkt->metadata_ = FaultMask;
  return std::unique_ptr<MemPacket>(pkt);
}

}  // namespace memory
}  // namespace simeng
