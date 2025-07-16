#pragma once

#include "simeng/Instruction.hh"

namespace simeng {
namespace pipeline {
namespace noc {

/** A Network-on-Chip packet, parametrized over the data type. */
template <typename D>
struct NocPacket {
  D data_;
};

/** A Network-on-Chip endec (encoder/decoder), parametrized over both out-bound
 * and in-bound packet data types. */
template <typename Out, typename In>
class NocEndec {
 public:
  /** Creates a new NoC packet based on the provided arguments. */
  template <typename... Args>
  static NocPacket<Out> encode(Args... args) {
    Out data(args...);
    return {std::move(data)};
  }

  /** Converts the incoming NoC packet into `T` using `In.into()`. */
  template <typename T>
  static T decode(NocPacket<In> packet) {
    return packet.data_.into();
  }
};

}  // namespace noc
}  // namespace pipeline
}  // namespace simeng
