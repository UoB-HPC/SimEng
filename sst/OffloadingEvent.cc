#include "OffloadingEvent.hh"

namespace SST {
namespace SSTSimEng {

using namespace simeng;

OffloadingEvent::OffloadingEvent(const packet_t& packet) {
  const auto& payload = packet.data_.payload_;
  payload.serializeInto(serialized_);
}

OffloadingEvent::packet_t OffloadingEvent::deserialize(
    const arch::Architecture& architecture) const {
  span bytes = {const_cast<uint8_t*>(serialized_.data()), serialized_.size()};
  auto payload = OffloadingPayload::deserialize(architecture, bytes);
  return {AcceleratorPacket(std::move(payload))};
}

void OffloadingEvent::serialize_order(Core::Serialization::serializer& ser) {
  Event::serialize_order(ser);
  ser & serialized_;
}

}  // namespace SSTSimEng
}  // namespace SST
