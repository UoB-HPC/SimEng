#pragma once

#include <deque>
#include <optional>

#include "simeng/pipeline/noc/NocEndec.hh"

namespace simeng {
namespace pipeline {
namespace noc {

/** A Network-on-Chip gateway for sending and receiving packets,
 * parametrized over both out-bound and in-bound packet data types. */
template <typename Out, typename OutP, typename In = Out, typename InP = OutP>
class NocGateway {
 public:
  /** The function type for sending packets over the NoC. It takes a reference
   * to the packet and returns whether it has been successfully sent. */
  using send_fn_t = std::function<bool(const NocPacket<OutP>&)>;

  /** The function type for receiving packets from the NoC. Returns the latest
   * packet received from the network, if there are any. */
  using receive_fn_t = std::function<std::optional<NocPacket<InP>>()>;

  NocGateway(send_fn_t send, receive_fn_t receive)
      : send_(send), receive_(receive) {}

  /** Tick the out-bound part of the gateway. Propagates elements in the
   * internal pipeline, inserting the provided item into a queue
   * (if applicable), and sending packets over the NoC. */
  void tickOutbound(std::optional<Out> item) {
    // Operations are performed in reverse to preserve latencies
    send();
    encode();
    schedule(std::move(item));
  }

  /** Tick the in-bound part of the gateway. Propagates elements in the internal
   * pipeline, receiving packets from the NoC, and returning the latest
   * processed item (if there is one). */
  std::optional<In> tickInbound() {
    // Operations are performed in reverse to preserve latencies
    auto item = decode();
    receive();
    return item;
  }

  // TODO: Flushing?

 private:
  /** Puts the provided item at the back of the encoding queue. */
  void schedule(std::optional<Out> item) {
    if (!item.has_value()) return;
    encodeQueue_.push_back(std::move(item.value()));
  }

  /** Takes out an item from the front of the encoding queue, encodes it,
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
    if (sendQueue_.empty()) return;

    if (send_(sendQueue_.front())) {
      // Packet successfully sent, remove from the queue
      sendQueue_.pop_front();
    }
  }

  /** Receives an incoming packet (if there is one),
   * and puts it at the back of the decoding queue. */
  void receive() {
    auto packet = receive_();
    if (!packet.has_value()) return;
    decodeQueue_.push_back(std::move(packet.value()));
  }

  /** Takes out a packet from the front of the decoding queue, decodes it,
   * and returns the resulting item. */
  std::optional<In> decode() {
    if (decodeQueue_.empty()) return {};

    auto packet = std::move(decodeQueue_.front());
    decodeQueue_.pop_front();
    return endec_.template decode<In>(std::move(packet));
  }

  /** Packet Endec (encoder/decoder). */
  NocEndec<OutP, InP> endec_;

  /** A queue for items to be packetized. */
  std::deque<Out> encodeQueue_;

  /** A queue for packets to be sent over the NoC. */
  std::deque<NocPacket<OutP>> sendQueue_;

  /** A queue for packets received from the NoC, waiting to be decoded. */
  std::deque<NocPacket<InP>> decodeQueue_;

  /** A function for sending packets over the NoC. */
  send_fn_t send_;

  /** A function for receiving packets from the NoC. */
  receive_fn_t receive_;
};

}  // namespace noc
}  // namespace pipeline
}  // namespace simeng