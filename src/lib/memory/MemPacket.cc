#include "simeng/memory/MemPacket.hh"

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

MemPacket* MemPacket::createReadRequest(uint64_t address, uint64_t size,
                                        uint64_t reqId) {
  return new MemPacket(address, size, READ_REQUEST, reqId);
}

MemPacket* MemPacket::createWriteRequest(uint64_t address, uint64_t size,
                                         uint64_t reqId,
                                         std::vector<char> data) {
  return new DataPacket(address, size, WRITE_REQUEST, reqId, data);
}

MemPacket* MemPacket::createReadResponse(uint64_t address, uint64_t size,
                                         uint64_t reqId,
                                         std::vector<char> data) {
  return new DataPacket(address, size, READ_RESPONSE, reqId, data);
}

MemPacket* MemPacket::createWriteResponse(uint64_t address, uint64_t size,
                                          uint64_t reqId) {
  return new MemPacket(address, size, WRITE_RESPONSE, reqId);
}

MemPacket* MemPacket::createFaultyMemPacket() {
  MemPacket* pkt = new MemPacket;
  pkt->metadata_ = FaultMask;
  pkt->id_ = 0;
  pkt->address_ = 0;
  pkt->size_ = 0;
  return pkt;
}

MemPacket* MemPacket::makeIntoReadResponse(std::vector<char> data) {
  return MemPacket::createReadResponse(address_, size_, id_, data);
}

MemPacket* MemPacket::makeIntoWriteResponse() {
  std::cerr << "Invalid conversion for MemPacket. Base MemPacket can only be "
               "of type READ_REQUEST or WRITE_RESPONSE and cannot be converted "
               "to a WRITE_RESPONE"
            << std::endl;
  std::exit(1);
}

DataPacket::DataPacket(uint64_t address, uint64_t size, MemPacketType type,
                       uint64_t reqId, std::vector<char> data)
    : MemPacket(address, size, type, reqId) {
  metadata_ = metadata_ | PayloadMask;
  data_ = data;
}

MemPacket* DataPacket::makeIntoWriteResponse() {
  return MemPacket::createWriteResponse(address_, size_, id_);
}

MemPacket* DataPacket::makeIntoReadResponse(std::vector<char> data) {
  std::cerr << "Invalid conversion for DataPacket. DataPacket can only be of "
               "type READ_RESPONSE or WRITE_REQUEST and cannot be converted "
               "into to a READ_RESPONE."
            << std::endl;
  std::exit(1);
}

}  // namespace memory
}  // namespace simeng
