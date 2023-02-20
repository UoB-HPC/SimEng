#include "simeng/memory/Mem.hh"

#include <utility>

namespace simeng {
namespace memory {

DataPacket::DataPacket(uint64_t address, uint64_t size, DataPacketType type,
                       uint64_t reqId, bool fault)
    : address_(address),
      size_(size),
      type_(type),
      id_(reqId),
      inFault_(fault) {}

DataPacket::DataPacket(uint64_t address, uint64_t size, DataPacketType type,
                       uint64_t reqId, std::vector<char> data, bool fault)
    : address_(address),
      size_(size),
      type_(type),
      id_(reqId),
      data_(data),
      inFault_(fault) {}

DataPacket DataPacket::makeIntoReadResponse(std::vector<char> data) {
  // If type of DataPacket isn't READ_REQUEST return faulty DataPacket.
  if (type_ != READ_REQUEST) {
    std::cerr << "[SimEng:DataPacket] Cannot change DataPacket type to "
                 "READ_RESPONSE as the request type isn't READ_REQUEST."
              << std::endl;
    return DataPacket(true);
  }
  type_ = READ_RESPONSE;
  data_ = data;
  inFault_ = false;
  return *this;
}

DataPacket DataPacket::makeIntoWriteResponse() {
  // If type of DataPacket isn't WRITE_REQUEST return faulty DataPacket.
  if (type_ != WRITE_REQUEST) {
    std::cerr << "[SimEng:DataPacket] Cannot change DataPacket type to "
                 "WRITE_RESPONSE as the request type isn't WRITE_REQUEST."
              << std::endl;
    return DataPacket(true);
  }
  type_ = WRITE_RESPONSE;
  inFault_ = false;
  return *this;
}

}  // namespace memory
}  // namespace simeng
