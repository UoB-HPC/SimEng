#pragma once

#include "simeng/Instruction.hh"

namespace simeng {
namespace pipeline {
namespace noc {

/** The payload sent to the NoC gateway by the offloading controller. */
// TODO: Split into core->acc & acc->core payloads
struct OffloadingPayload {
  using id_t = uint64_t;

  /** Type of payload, specifying what kind of data is sent. */
  enum class Type : uint8_t {
    /** Tells the accelerator to schedule the attached instruction. */
    Schedule,
    /** Tells the core the attached instruction has been commited
     * by the accelerator. */
    Commit,
    /** Tells the core to flush after an instruction associated with
     * the provided payload ID. */
    Flush,
    /** Tells the accelerator the flush request with the provided ID has been
     * finalized. */
    Flushed,
  };

  /** Payload ID. Packets that deal with the same instruction have the same
   * payload ID. */
  id_t id_;

  /** The type of payload. */
  Type type_;

  /** Offloaded instruction. Valid only when `type_` is equal to either
   * `Schedule` or `Commit`. */
  std::shared_ptr<Instruction> insn_;

  static OffloadingPayload schedule(const id_t id,
                                    std::shared_ptr<Instruction> insn) {
    return OffloadingPayload(id, Type::Schedule, std::move(insn));
  }

  static OffloadingPayload commit(const id_t id,
                                  std::shared_ptr<Instruction> insn) {
    return OffloadingPayload(id, Type::Commit, std::move(insn));
  }

  static OffloadingPayload flush(const id_t id) {
    return OffloadingPayload(id, Type::Flush);
  }

  static OffloadingPayload confirmFlush(const id_t id) {
    return OffloadingPayload(id, Type::Flushed);
  }

 private:
  OffloadingPayload(const id_t id, const Type type,
                    std::shared_ptr<Instruction> insn)
      : id_(id), type_(type), insn_(std::move(insn)) {}

  OffloadingPayload(const id_t id, const Type type)
      : id_(id), type_(type), insn_(nullptr) {}
};

}  // namespace noc
}  // namespace pipeline
}  // namespace simeng
