#pragma once

#include "simeng/Instruction.hh"

namespace simeng {
namespace pipeline {
namespace noc {

/** A Network-on-Chip packet, parametrized over the data type. */
template <typename D>
struct NocPacket {
  using id_t = uint64_t;

  id_t id_;
  D data_;
};

/** A Network-on-Chip endec (encoder/decoder), parametrized over both out-bound
 * and in-bound packet data types. */
template <typename Out, typename In>
class NocEndec {
 public:
  /** Creates a new NoC packet based on the provided instruction and other
   * arguments. */
  template <typename... Args>
  NocPacket<Out> encode(std::shared_ptr<Instruction> insn, Args... args) {
    // Create the data
    const auto& insn_arg = insn;
    In data(insn_arg, args...);

    // Register the packet
    const auto id = new_id++;
    encoded_.insert({id, std::move(insn)});

    return {id, std::move(data)};
  }

  /** Updates the instruction associated with the provided packet's ID using
   * the packet's data. The return optional has a value if the instruction
   * hasn't been flushed. */
  std::optional<std::shared_ptr<Instruction>> decode(NocPacket<In> packet) {
    const auto id = packet.id_;
    auto insn = std::move(encoded_[id]);
    encoded_.erase(id);
    if (insn == nullptr || insn->isFlushed()) {
      return {};
    }

    packet.data_.updateInstruction(insn);
    return insn;
  }

  /** Determines whether the instruction associated with the provided packet has
   * been flushed. */
  template <typename T>
  bool isPacketFlushed(const NocPacket<T>& packet) const {
    const auto& insn = encoded_.at(packet.id_);
    return insn->isFlushed();
  }

 private:
  using packet_id_t = typename NocPacket<Out>::id_t;

  /** Instructions that have been encoded, and are in-flight
   * (i.e. a returning packet hasn't been decoded). */
  std::unordered_map<packet_id_t, std::shared_ptr<Instruction>> encoded_;

  /** A packet ID that will be assigned to the next encoded packet. */
  packet_id_t new_id = 0;
};

}  // namespace noc
}  // namespace pipeline
}  // namespace simeng
