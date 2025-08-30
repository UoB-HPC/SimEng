#include "simeng/arch/Architecture.hh"
#include "simeng/serialization.hh"

namespace simeng {
namespace pipeline {
namespace noc {

OffloadingPayload OffloadingPayload::schedule(
    const id_t id, std::shared_ptr<Instruction> insn) {
  return {id, Type::Schedule, std::move(insn)};
}

OffloadingPayload OffloadingPayload::commit(const id_t id,
                                            std::shared_ptr<Instruction> insn) {
  return {id, Type::Commit, std::move(insn)};
}

OffloadingPayload OffloadingPayload::flush(const id_t id) {
  return {id, Type::Flush};
}

OffloadingPayload OffloadingPayload::confirmFlush(const id_t id) {
  return {id, Type::Flushed};
}

void OffloadingPayload::serializeInto(std::vector<uint8_t>& buffer) const {
  serialize_field(buffer, id_);
  serialize_field(buffer, type_);
  switch (type_) {
    case Type::Schedule:
    case Type::Commit: {
      // insn_->serializeInto(buffer);

      // TODO: Get rid of this once serialization starts working
      {
        auto insn = insn_->clone();
        auto* insn_ptr = insn.release();
        serialize_field(buffer, insn_ptr);
      }

      break;
    }
    case Type::Flush:
    case Type::Flushed: {
      break;
    }
  }
}

OffloadingPayload OffloadingPayload::deserialize(
    const arch::Architecture& architecture, span<uint8_t>& serialized) {
  id_t id = 0;
  auto type = Type::Schedule;
  deserialize_field(serialized, id);
  deserialize_field(serialized, type);
  switch (type) {
    case Type::Schedule:
    case Type::Commit: {
      auto insn = architecture.deserializeFrom(serialized);
      return {id, type, std::move(insn)};
    }
    case Type::Flush:
    case Type::Flushed: {
      return {id, type};
    }
  }
  assert(false && "Unreachable");
}

OffloadingPayload::OffloadingPayload(const id_t id, const Type type,
                                     std::shared_ptr<Instruction> insn)
    : id_(id), type_(type), insn_(std::move(insn)) {}

OffloadingPayload::OffloadingPayload(const id_t id, const Type type)
    : id_(id), type_(type), insn_(nullptr) {}

}  // namespace noc
}  // namespace pipeline
}  // namespace simeng
