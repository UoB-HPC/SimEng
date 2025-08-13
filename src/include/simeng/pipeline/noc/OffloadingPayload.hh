#pragma once

#include "simeng/Instruction.hh"

namespace simeng {
namespace pipeline {
namespace noc {

/** Type of payload, specifying what kind of data is sent. */
enum class OffloadingPayloadType : uint8_t {
  /** Tells the accelerator to schedule the attached instruction. */
  Schedule,
  /** Tells the accelerator to commit an instruction with the provided
   * sequence ID and send a response. */
  CommitRequest,
  /** Tells the core the attached instruction has been commited
   * by the accelerator. */
  CommitResponse,
  /** Tells the accelerator to flush an instruction with the provided
   * sequence ID. */
  Flush,
};

/** The payload sent to the NoC gateway by the offloading controller. */
struct OffloadingPayload {
  using id_t = uint64_t;

  /** Unique ID of a Payload instance. */
  id_t id_;

  /** The type of payload. */
  OffloadingPayloadType type_;

  /** Sequence ID on the core of the instruction that this payload is concerned
   * with. If `insn_` is valid, it is the same as that instruction's
   * sequence ID. */
  uint64_t seqId_;

  /** Offloaded instruction. Valid only when `type_` is equal to either
   * `Schedule` or `CommitResponse`. */
  std::shared_ptr<Instruction> insn_;

  static OffloadingPayload schedule(const id_t id,
                                    std::shared_ptr<Instruction> insn) {
    return OffloadingPayload(id, OffloadingPayloadType::Schedule,
                             std::move(insn));
  }

  static OffloadingPayload requestCommit(const id_t id,
                                         const Instruction& insn) {
    return OffloadingPayload(id, OffloadingPayloadType::CommitRequest, insn);
  }

  static OffloadingPayload confirmCommit(const id_t id,
                                         std::shared_ptr<Instruction> insn) {
    return OffloadingPayload(id, OffloadingPayloadType::CommitResponse,
                             std::move(insn));
  }

  static OffloadingPayload flush(const id_t id, const Instruction& insn) {
    return OffloadingPayload(id, OffloadingPayloadType::Flush, insn);
  }

 private:
  OffloadingPayload(const id_t id, const OffloadingPayloadType type,
                    std::shared_ptr<Instruction> insn)
      : id_(id),
        type_(type),
        seqId_(insn->getSequenceId()),
        insn_(std::move(insn)) {}

  OffloadingPayload(const id_t id, const OffloadingPayloadType type,
                    const Instruction& insn)
      : id_(id), type_(type), seqId_(insn.getSequenceId()), insn_(nullptr) {}
};

}  // namespace noc
}  // namespace pipeline
}  // namespace simeng
