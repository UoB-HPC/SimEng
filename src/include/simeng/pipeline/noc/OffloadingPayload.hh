#pragma once

#include "simeng/Instruction.hh"

namespace simeng {
namespace arch {
class Architecture;
}  // namespace arch
}  // namespace simeng

namespace simeng {
namespace pipeline {
namespace noc {

/** The payload sent to the NoC gateway by the offloading controller. */
// TODO: Split into separate core->acc & acc->core payloads
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

  /** Creates a new payload for scheduling an instruction to be offloaded. */
  static OffloadingPayload schedule(id_t id, std::shared_ptr<Instruction> insn);

  /** Creates a new payload for commiting an offloaded instruction. */
  static OffloadingPayload commit(id_t id, std::shared_ptr<Instruction> insn);

  /** Creates a new payload for requesting a flush. */
  static OffloadingPayload flush(id_t id);

  /** Creates a new payload for confirming a flush. */
  static OffloadingPayload confirmFlush(id_t id);

  /** Serializes the payload into the provided buffer. */
  void serializeInto(std::vector<uint8_t>& buffer) const;

  /** Deserializes the provided bytes, based on the provided architecture. */
  static OffloadingPayload deserialize(const arch::Architecture& architecture,
                                       span<uint8_t>& serialized);

 private:
  OffloadingPayload(id_t id, Type type, std::shared_ptr<Instruction> insn);

  OffloadingPayload(id_t id, Type type);
};

}  // namespace noc
}  // namespace pipeline
}  // namespace simeng
