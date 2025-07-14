#pragma once

#include <deque>
#include <optional>

#include "simeng/pipeline/noc/NocEndec.hh"

namespace simeng {
namespace pipeline {
namespace noc {

/** A Network-on-Chip gateway for sending and receiving packets,
 * parametrized over both out-bound and in-bound packet data types. */
template <typename Out, typename In>
class NocGateway {
  using opt_insn_t = std::optional<std::shared_ptr<Instruction>>;

 public:
  /** Tick the gateway. Propagates elements in the internal pipeline,
   * inserting the provided uop into a queue (if applicable), and returning
   * the latest processed instruction (if there is one). */
  opt_insn_t tick(opt_insn_t uop) {
    // Operations are performed in reverse to preserve latencies

    const auto insn = decode();
    receive();
    send();
    encode();
    schedule(std::move(uop));

    return insn;
  }

  /** Purge flushed instructions from the internal pipeline. */
  void purgeFlushed() {
    const auto& endec = endec_;
    purgeQueue<std::shared_ptr<Instruction>>(
        encodeQueue_, [](const auto& insn) { return insn->isFlushed(); });
    purgeQueue<NocPacket<Out>>(sendQueue_, [endec](const auto& packet) {
      return endec.isPacketFlushed(packet);
    });
    purgeQueue<NocPacket<In>>(decodeQueue_, [endec](const auto& packet) {
      return endec.isPacketFlushed(packet);
    });
  }

 private:
  /** Puts the provided uop at the back of the encoding queue. */
  void schedule(opt_insn_t uop) {
    if (!uop.has_value()) return;
    encodeQueue_.push_back(std::move(uop.value()));
  }

  /** Takes out an instruction from the front of the encoding queue, encodes it,
   * and puts the resulting packet at the back of the sending queue. */
  void encode() {
    if (encodeQueue_.empty()) return;

    auto packet = endec_.encode(std::move(encodeQueue_.front()));
    encodeQueue_.pop_front();
    sendQueue_.push_back(std::move(packet));
  }

  /** Takes out a packet from the front of the sending queue,
   * and sends it over the network. */
  void send() {
    // TODO: Implement sending
  }

  /** Receives an incoming packet (if there is one),
   * and puts it at the back of the decoding queue. */
  void receive() {
    // TODO: Implement receiving

    if (sendQueue_.empty()) return;
    decodeQueue_.push_back(std::move(sendQueue_.front()));
    sendQueue_.pop_front();
  }

  /** Takes out a packet from the front of the decoding queue, decodes it,
   * and returns the resulting instruction. */
  opt_insn_t decode() {
    if (decodeQueue_.empty()) return {};

    auto packet = std::move(decodeQueue_.front());
    decodeQueue_.pop_front();
    return endec_.decode(std::move(packet));
  }

  /** Removes all the flushed elements from the provided queue, based on the
   * `isFlushed` check. */
  template <typename T>
  static void purgeQueue(std::deque<T>& queue,
                         std::function<bool(const T&)> isFlushed) {
    auto it = queue.begin();
    while (it != queue.end()) {
      const auto& item = *it;
      if (isFlushed(item)) {
        it = queue.erase(it);
      } else {
        ++it;
      }
    }
  }

  /** Packet Endec (encoder/decoder). */
  NocEndec<Out, In> endec_;

  /** A queue for instructions to be packetized. */
  std::deque<std::shared_ptr<Instruction>> encodeQueue_;

  /** A queue for packets to be sent over the NoC. */
  std::deque<NocPacket<Out>> sendQueue_;

  /** A queue for packets received from the NoC, waiting to be decoded. */
  std::deque<NocPacket<In>> decodeQueue_;
};

}  // namespace noc
}  // namespace pipeline
}  // namespace simeng