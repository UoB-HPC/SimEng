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

DataPacket::DataPacket(const DataPacket& packet)
    : address_(packet.address_),
      size_(packet.size_),
      type_(packet.type_),
      id_(packet.id_),
      data_(packet.data_),
      inFault_(packet.inFault_) {}

DataPacket::DataPacket(DataPacket&& packet)
    : address_(std::exchange(packet.address_, 0)),
      size_(std::exchange(packet.size_, 0)),
      type_(std::exchange(packet.type_, NONE)),
      id_(std::exchange(packet.id_, 0)),
      data_(std::move(packet.data_)),
      inFault_(std::exchange(packet.inFault_, 0)) {}

DataPacket& DataPacket::operator=(const DataPacket& packet) {
  address_ = packet.address_;
  size_ = packet.size_;
  type_ = packet.type_;
  id_ = packet.id_;
  data_ = packet.data_;
  inFault_ = packet.inFault_;
  return *this;
}

DataPacket& DataPacket::operator=(DataPacket&& packet) {
  address_ = std::exchange(packet.address_, 0);
  size_ = std::exchange(packet.size_, 0);
  type_ = std::exchange(packet.type_, NONE);
  id_ = std::exchange(packet.id_, 0);
  data_ = std::move(packet.data_);
  inFault_ = std::exchange(packet.inFault_, 0);
  return *this;
}

DataPacket DataPacket::makeIntoReadResponse(std::vector<char> data) {
  // If type of DataPacket isn't READ_REQUEST return faulty DataPacket.
  if (type_ != READ_REQUEST) {
    std::cerr << "[SimEng::DataPacket] Cannot change DataPacket type to "
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
    std::cerr << "[SimEng::DataPacket] Cannot change DataPacket type to "
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
