#include "simeng/memory/MemPacket.hh"

#include <memory>
#include <vector>

namespace simeng {
namespace memory {

MemPacket::MemPacket(uint64_t vaddr, uint16_t size, MemPacketType type,
                     uint64_t reqId)
    : vaddr_(vaddr), size_(size), id_(reqId), metadata_(type) {}

MemPacket::MemPacket(uint64_t vaddr, uint16_t size, MemPacketType type,
                     uint64_t reqId, std::vector<char> payload)
    : vaddr_(vaddr),
      size_(size),
      id_(reqId),
      metadata_(type),
      payload_(payload) {}

std::unique_ptr<MemPacket> MemPacket::createReadRequest(uint64_t vaddr,
                                                        uint16_t size,
                                                        uint64_t reqId) {
  return std::unique_ptr<MemPacket>(
      new MemPacket(vaddr, size, READ_REQUEST, reqId));
}

std::unique_ptr<MemPacket> MemPacket::createWriteRequest(
    uint64_t vaddr, uint16_t size, uint64_t reqId, std::vector<char> payload) {
  return std::unique_ptr<MemPacket>(
      new MemPacket(vaddr, size, WRITE_REQUEST, reqId, payload));
}

void MemPacket::turnIntoWriteResponse() {
  if (!isRequest() && !isWrite()) {
    std::cerr << "[SimEng:MemPacket] Only MemPackets of type Write Request can "
                 "be changed into Write Response"
              << std::endl;
    std::exit(1);
  }
  // Turn into response, maintaining other metadata
  metadata_ = metadata_ & 0b01111111;
}

void MemPacket::turnIntoReadResponse(std::vector<char> payload) {
  if (!isRequest() && !isRead()) {
    std::cerr << "[SimEng:MemPacket] Only MemPackets of type Read Request can "
                 "be changed into Read Response"
              << std::endl;
    std::exit(1);
  }
  // Turn into response, maintaining other metadata
  metadata_ = metadata_ & 0b01111111;
  payload_ = payload;
}

}  // namespace memory
}  // namespace simeng
