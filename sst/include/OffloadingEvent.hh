#pragma once

#include <sst/core/event.h>

#include "simeng/Accelerator.hh"
#include "simeng/pipeline/noc/NocEndec.hh"

namespace SST {
namespace SSTSimEng {

using namespace simeng;

/** An SST::Event for sending AcceleratorPackets. */
class OffloadingEvent final : public Event {
 public:
  /** Type of NoC packet held by this event. */
  using packet_t = NocPacket<AcceleratorPacket>;

  /** Creates a new event, serializing the provided packet. */
  explicit OffloadingEvent(const packet_t& packet);

  /** Deserializes contained bytes into a packet object. */
  [[nodiscard]] packet_t deserialize(
      const arch::Architecture& architecture) const;

  void serialize_order(Core::Serialization::serializer& ser) override;

 private:
  /** Private constructor used by SST serialization. */
  OffloadingEvent() : serialized_({}) {}

  /** Serialized representation of the NoC packet. */
  std::vector<uint8_t> serialized_;

  ImplementSerializable(SST::SSTSimEng::OffloadingEvent);
};

}  // namespace SSTSimEng
}  // namespace SST
